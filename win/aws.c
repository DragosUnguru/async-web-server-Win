#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <winsock2.h>
#include <mswsock.h>

#include "sock_util.h"
#include "w_iocp.h"
#include "../http-parser/http_parser.h"
#include "../util.h"
#include "../aws.h"
#include "../debug.h"

#ifndef BUFSIZ
#define BUFSIZ				8192
#endif

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

/* server socket file handle */
static SOCKET listenfd;

/* IoCompletionPort handle */
static HANDLE iocp;

enum connection_state {
	STATE_INIT,
	STATE_DATA_RECEIVED,
	STATE_DATA_SENT,
	STATE_DATA_PENDING,
	STATE_DATA_HEADER,
	STATE_CONNECTION_CLOSED
};

enum file_type {
	DYNAMIC,
	STATIC,
	INVALID
};

/* structure acting as a connection handler */
struct connection {
	SOCKET sockfd;
	HANDLE hFile;
	char recv_buffer[BUFSIZ];
	char send_buffer[BUFSIZ];
	char dynamic_buffer[BUFSIZ];
	/* buffers used for receiving messages and then echoing them back */
	WSABUF recv_buffers[1];
	WSABUF send_buffers[1];
	size_t bytes_recv;
	size_t bytes_sent;
	size_t bytes_read;
	WSAOVERLAPPED recv_ov;
	WSAOVERLAPPED send_ov;
	OVERLAPPED read_ov;
	DWORD fileSize;
	enum file_type fileType;
	enum connection_state state;
};

/*
 * Anonymous structure used to "confine" data regardin asynchronous accept
 * operations (handled through AcceptEx and Io Completion Ports).
 */
static struct {
	SOCKET sockfd;
	char buffer[BUFSIZ];
	size_t len;
	OVERLAPPED ov;
} ac;

/*
 * HTTP-parser. Structures needed to fetch the demanded path
 * to the file.
 */
static http_parser request_parser;
static char request_path[BUFSIZ];

static void connection_complete_socket_send(struct connection *conn,
	WSAOVERLAPPED *ovp);
static void connection_schedule_static(struct connection *conn,
	WSAOVERLAPPED *ovp);
static void connection_schedule_dynamic(struct connection *conn);

/*
 * Initialize connection structure on given socket.
 */

static struct connection *connection_create(SOCKET sockfd)
{
	struct connection *conn = malloc(sizeof(*conn));

	DIE(conn == NULL, "malloc");

	conn->sockfd = sockfd;
	conn->hFile = NULL;
	ZeroMemory(conn->recv_buffer, BUFSIZ);
	ZeroMemory(conn->send_buffer, BUFSIZ);
	ZeroMemory(conn->dynamic_buffer, BUFSIZ);
	conn->recv_buffers[0].buf = conn->recv_buffer;
	conn->send_buffers[0].buf = conn->send_buffer;
	conn->recv_buffers[0].len = BUFSIZ;
	conn->send_buffers[0].len = BUFSIZ;
	conn->fileSize = 0;
	conn->bytes_recv = 0;
	conn->bytes_sent = 0;
	conn->bytes_recv = 0;
	conn->fileType = INVALID;
	conn->state = STATE_INIT;

	ZeroMemory(&conn->recv_ov, sizeof(conn->recv_ov));
	ZeroMemory(&conn->send_ov, sizeof(conn->send_ov));
	ZeroMemory(&conn->read_ov, sizeof(conn->read_ov));

	return conn;
}

/*
 * Add a non bound socket to the connection. The socket is to be bound
 * by AcceptEx.
 */

static struct connection *connection_create_with_socket(void)
{
	SOCKET s;

	s = socket(PF_INET, SOCK_STREAM, 0);
	DIE(s == INVALID_SOCKET, "socket");

	return connection_create(s);
}

/*
 * Remove connection handler.
 */

static void connection_remove(struct connection *conn)
{
	closesocket(conn->sockfd);
	if (conn->hFile != NULL)
		CloseHandle(conn->hFile);
	free(conn);
}

/*
 * Callback is invoked by HTTP request parser when parsing request path.
 * Request path is stored in global request_path variable.
 */

static int on_path_cb(http_parser *p, const char *buf, size_t len)
{
	assert(p == &request_parser);
	memcpy(request_path, buf, len);

	return 0;
}

/* Use mostly null settings except for on_path callback. */
static http_parser_settings settings_on_path = {
	/* on_message_begin */ 0,
	/* on_header_field */ 0,
	/* on_header_value */ 0,
	/* on_path */ on_path_cb,
	/* on_url */ 0,
	/* on_fragment */ 0,
	/* on_query_string */ 0,
	/* on_body */ 0,
	/* on_headers_complete */ 0,
	/* on_message_complete */ 0
};

/*
 * Call http_parser to parse sample_request. Subsequently print request_path
 * as filled by callback.
 * Callback is on_path_cb as setup in settings_on_path.
 */

/*
 * Sets global "request_path" to the
 * demanded file's path received as a request
 * to the calee
 */
static void fetch_request_path(const char *request)
{
	size_t bytes_parsed;

	/* init HTTP_REQUEST parser */
	http_parser_init(&request_parser, HTTP_REQUEST);
	ZeroMemory(request_path, BUFSIZ);


	bytes_parsed = http_parser_execute(
		&request_parser,
		&settings_on_path,
		request,
		strlen(request)
	);
}

static void put_header(struct connection *conn)
{
	char buffer[BUFSIZ];

	sprintf_s(buffer, BUFSIZ,
		"^HTTP/1.1 200 OK\r\n"
		"Date: Sun, 10 Oct 2010 23:26:07 GMT\r\n"
		"Server: Apache/2.2.8 (Ubuntu) mod_ssl/2.2.8 OpenSSL/0.9.8g\r\n"
		"Last-Modified: Mon, 02 Aug 2010 17:55:28 GMT\r\n"
		"Accept-Ranges: bytes\r\n"
		"Content-Length: %ld\r\n"
		"Vary: Accept-Encoding\r\n"
		"Connection: close\r\n"
		"Content-Type: text/html\r\n"
		"\r\n", conn->fileSize);
	memcpy(conn->send_buffer, buffer, strlen(buffer));

	conn->send_buffers[0].buf = conn->send_buffer;
	conn->send_buffers[0].len = strlen(buffer);
}

static void put_error(struct connection *conn)
{
	static const char buffer[] =
		"^HTTP/1.1 404 Not Found\r\n"
		"Date: Sun, 08 May 2011 09:26:16 GMT\r\n"
		"Server: Apache/2.2.9\r\n"
		"Last-Modified: Mon, 02 Aug 2010 17:55:28 GMT\r\n"
		"Accept-Ranges: bytes\r\n"
		"Content-Length: 230\r\n"
		"Vary: Accept-Encoding\r\n"
		"Connection: close\r\n"
		"Content-Type: text/html\r\n"
		"\r\n";
	memcpy(conn->send_buffer, buffer, strlen(buffer));

	conn->send_buffers[0].buf = conn->send_buffer;
	conn->send_buffers[0].len = strlen(buffer);
}

/*
 * Use WSASend to asynchronously send message through socket.
 */

static void send_buffer(struct connection *conn)
{
	DWORD flags;
	int rc;

	ZeroMemory(&conn->send_ov, sizeof(conn->send_ov));
	flags = 0;

	rc = WSASend(
		conn->sockfd,
		conn->send_buffers,
		1,
		NULL,
		flags,
		&conn->send_ov,
		NULL);
	DIE(rc && (rc != SOCKET_ERROR || WSAGetLastError() != WSA_IO_PENDING),
		"WSASend");
}

static void connection_schedule_socket_send(struct connection *conn)
{
	/* Send HTTP response header */
	if (conn->fileType == INVALID) {
		put_error(conn);
		conn->state = STATE_DATA_SENT;
	} else {
		put_header(conn);
		conn->state = STATE_DATA_PENDING;
	}

	send_buffer(conn);
}

/*
 * Prepare data for overlapped I/O send operation.
 */

static void connection_prepare_socket_send(struct connection *conn)
{
	DWORD fileHighSize;
	char path[BUFSIZ];

	/* Get demanded file's name */
	fetch_request_path(conn->recv_buffer);

	/* Format path to file managing absolute path from root */
	sprintf_s(path, BUFSIZ, "%s%s", AWS_DOCUMENT_ROOT, request_path + 1);

	/* Manage file */
	conn->hFile = CreateFile(
		path,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_OVERLAPPED,
		NULL
	);

	/* File not found. Send 404 error */
	if (conn->hFile == INVALID_HANDLE_VALUE) {
		conn->fileType = INVALID;
		return;
	}

	/* Get file size */
	conn->fileSize = GetFileSize(conn->hFile, &fileHighSize);
	DIE(GetLastError() != NO_ERROR, "GetFileSize");

	conn->fileSize += fileHighSize << 8;

	/* If it's a static file, send by zero-copying */
	if (strstr(request_path, AWS_REL_STATIC_FOLDER) != NULL)
		conn->fileType = STATIC;

	/* If it's a dynamic file, send via WSASend */
	else if (strstr(request_path, AWS_REL_DYNAMIC_FOLDER) != NULL)
		conn->fileType = DYNAMIC;

	conn->state = STATE_DATA_HEADER;
}

static void connection_schedule_static(struct connection *conn,
	WSAOVERLAPPED *ovp)
{
	BOOL bRet;
	DWORD bytes_sent, flags;

	bRet = WSAGetOverlappedResult(
		conn->sockfd,
		ovp,
		&bytes_sent,
		FALSE,
		&flags
	);

	conn->bytes_sent += bytes_sent;

	/* Connection interrupted */
	if (bytes_sent <= 0) {
		conn->state = STATE_CONNECTION_CLOSED;
		return;
	}

	if (conn->bytes_sent < conn->fileSize) {
		bRet = TransmitFile(
			conn->sockfd,
			conn->hFile,
			0,
			0,
			&conn->send_ov,
			NULL,
			0
		);
		DIE(WSAGetLastError() != WSA_IO_PENDING, "TransmitFile");

		conn->state = STATE_DATA_PENDING;

		return;
	}

	conn->state = STATE_DATA_SENT;
	connection_remove(conn);
}

static void connection_schedule_dynamic(struct connection *conn)
{
	DWORD bytes;
	DWORD flags;
	DWORD bytesRead;
	BOOL bRet;

	flags = 0;

	bytes = MIN(conn->fileSize - conn->bytes_read, BUFSIZ);

	if (conn->bytes_read < conn->fileSize) {
		conn->read_ov.Offset = conn->bytes_sent;
		conn->read_ov.OffsetHigh = 0;

		bRet = ReadFile(
			conn->hFile,
			conn->dynamic_buffer,
			bytes,
			&bytesRead,
			&conn->read_ov
		);
		conn->state = STATE_DATA_PENDING;
		conn->bytes_read += bytesRead;

		return;
	}
}


/*
 * Use WSARecv to asynchronously receive message from socket.
 */

static void connection_schedule_socket_receive(struct connection *conn)
{
	DWORD flags;
	int rc;

	ZeroMemory(&conn->send_ov, sizeof(conn->send_ov));
	flags = 0;

	rc = WSARecv(
		conn->sockfd,
		conn->recv_buffers,
		1,
		NULL,
		&flags,
		&conn->recv_ov,
		NULL);
	DIE(rc && (rc != SOCKET_ERROR || WSAGetLastError() != WSA_IO_PENDING),
		"WSARecv");

	conn->state = STATE_DATA_RECEIVED;
}

/*
 * Overllaped I/O send operation completed (as signaled by I/O Completion
 * Port). Close connection.
 */

static void connection_complete_socket_send(struct connection *conn,
	WSAOVERLAPPED *ovp)
{
	/* Closing the socket also removes it from Completion port. */
	if (conn->state == STATE_CONNECTION_CLOSED ||
		conn->state == STATE_DATA_SENT)
		connection_remove(conn);

	else if (conn->state == STATE_DATA_PENDING &&
		conn->fileType == DYNAMIC) {
		if (!conn->bytes_read)
			w_iocp_add_key(iocp, conn->hFile, (ULONG_PTR)conn);

		connection_schedule_dynamic(conn);
	} else if (conn->state == STATE_DATA_PENDING &&
		conn->fileType == STATIC)
		connection_schedule_static(conn, ovp);

	else if (conn->state == STATE_DATA_HEADER)
		connection_schedule_socket_send(conn);

	else if (conn->state == STATE_DATA_RECEIVED)
		connection_prepare_socket_send(conn);

	else if (conn->state == STATE_INIT)
		connection_schedule_socket_receive(conn);
}

/*
 * Overllaped I/O receive operation completed (as signaled by I/O Completion
 * Port). Send message back.
 */

static void connection_complete_socket_receive(struct connection *conn,
	WSAOVERLAPPED *ovp)
{
	BOOL bRet;
	DWORD flags;
	DWORD recvBytes;

	bRet = WSAGetOverlappedResult(
		conn->sockfd,
		ovp,
		&recvBytes,
		FALSE,
		&flags
	);
	DIE(bRet == FALSE, "WSAGetOverlappedResult");

	conn->bytes_recv += recvBytes;

	/* In case of no bytes received, consider connection terminated. */
	if (recvBytes <= 0) {
		connection_remove(conn);
		return;
	}

	connection_prepare_socket_send(conn);
	connection_schedule_socket_send(conn);
}

/*
 * Schedule overlapped operation for accepting a new connection.
 */

static void create_iocp_accept(void)
{
	BOOL bRet;

	ZeroMemory(&ac, sizeof(ac));

	/* Create simple socket for acceptance */
	ac.sockfd = socket(PF_INET, SOCK_STREAM, 0);
	DIE(ac.sockfd == INVALID_SOCKET, "socket");

	/* Launch overlapped connection accept through AcceptEx. */
	bRet = AcceptEx(
		listenfd,
		ac.sockfd,
		ac.buffer,
		0,
		128,
		128,
		(LPDWORD) & ac.len,
		&ac.ov);
	DIE(bRet == FALSE && WSAGetLastError() != ERROR_IO_PENDING, "AcceptEx");
}

/*
 * Handle a new connection request on the server socket.
 */

static void handle_new_connection(void)
{
	struct connection *conn;
	char abuffer[64];
	HANDLE hRet;
	int rc;

	rc = setsockopt(
		ac.sockfd,
		SOL_SOCKET,
		SO_UPDATE_ACCEPT_CONTEXT,
		(char *)&listenfd,
		sizeof(listenfd)
	);
	DIE(rc < 0, "setsockopt");

	rc = get_peer_address(ac.sockfd, abuffer, 64);
	if (rc < 0) {
		ERR("get_peer_address");
		return;
	}

	/* Instantiate new connection handler. */
	conn = connection_create(ac.sockfd);

	/* Add socket to IoCompletionPort. */
	hRet = w_iocp_add_key(iocp, (HANDLE)conn->sockfd, (ULONG_PTR)conn);
	DIE(hRet != iocp, "w_iocp_add_key");

	/* Schedule receive operation. */
	connection_schedule_socket_receive(conn);

	/* Use AcceptEx to schedule new connection acceptance. */
	create_iocp_accept();
}

/*
 * Process overlapped I/O operation: data has been received from or
 * has been sent to the socket.
 */

static void handle_aio(struct connection *conn, OVERLAPPED *ovp)
{
	BOOL bRet;
	DWORD bytesRead = 0;

	if (ovp == &conn->send_ov)
		connection_complete_socket_send(conn, ovp);

	else if (ovp == &conn->recv_ov)
		connection_complete_socket_receive(conn, ovp);

	else if (ovp == &conn->read_ov) {
		/* Get no. of read bytes */
		bRet = GetOverlappedResult(
			conn->hFile,
			&conn->read_ov,
			&bytesRead,
			FALSE
		);
		conn->bytes_sent += bytesRead;

		/* Connection terminated */
		if (!bytesRead) {
			connection_remove(conn);
			return;
		}

		/* Manage read and sending buffers */
		ZeroMemory(conn->send_buffer, BUFSIZ);
		memcpy(conn->send_buffer, conn->dynamic_buffer, bytesRead);
		ZeroMemory(conn->dynamic_buffer, BUFSIZ);

		/* Send read data */
		conn->send_buffers[0].len = bytesRead;
		conn->send_buffers[0].buf = conn->send_buffer;
		send_buffer(conn);

		if (conn->bytes_sent == conn->fileSize)
			conn->state = STATE_DATA_SENT;
	}
}

int main(void)
{
	BOOL bRet;
	HANDLE hRet;

	wsa_init();

	iocp = w_iocp_create();
	DIE(iocp == NULL, "w_iocp_create");

	/* Create server socket. */
	listenfd = tcp_create_listener(AWS_LISTEN_PORT,
		DEFAULT_LISTEN_BACKLOG);
	DIE(listenfd == INVALID_SOCKET, "tcp_create_listener");

	hRet = w_iocp_add_handle(iocp, (HANDLE)listenfd);
	DIE(hRet != iocp, "w_iocp_add_handle");

	/* Use AcceptEx to schedule new connection acceptance. */
	create_iocp_accept();

	/* server main loop */
	while (1) {
		OVERLAPPED *ovp;
		ULONG_PTR key;
		DWORD bytes;

		/* Wait for overlapped I/O. */
		bRet = w_iocp_wait(iocp, &bytes, &key, &ovp);

		if (bRet == FALSE) {
			DWORD err;

			err = GetLastError();
			if (err == ERROR_NETNAME_DELETED) {
				connection_remove((struct connection *) key);
				continue;
			}
			DIE(bRet == FALSE, "w_iocp_wait");
		}

		/*
		 * Switch I/O notification types. Consider
		 *   - new connection requests (on server socket);
		 *   - socket communication (on connection sockets).
		 */

		if (key == listenfd)
			handle_new_connection();
		else
			handle_aio((struct connection *) key, ovp);
	}

	wsa_cleanup();

	return 0;
}

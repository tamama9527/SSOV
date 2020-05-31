import asyncio

async def handle_echo(reader, writer):
	data = await reader.read(1024)
	message = data.decode()
	addr = writer.get_extra_info('peername')

	print(f"Received {message!r} from {addr!r}")

	print(f"Send: {message!r}")
	writer.write(data)
	await writer.drain()

	print("Close the connection")
	writer.close()

async def main():
	ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
	ssl_context.check_hostname = False
	ssl_context.load_cert_chain('as.crt', 'as.pem')
	server = await asyncio.start_server(
		handle_echo, '127.0.0.1', 10021,ssl=ssl_context)

	addr = server.sockets[0].getsockname()
	print(f'Serving on {addr}')
	try:
		async with server:
			await server.serve_forever()
	except KeyboardInterrupt:
		return


	


if __name__ == '__main__':
	asyncio.run(main())

import asyncio


authorization_server=('127.0.0.1',10021)
application_service=('127.0.0.1',10022)

async def tcp_echo_client(host,message):
	ip,port=host
	
	reader,writer=await asyncio.open_connection(ip,port)

	print(f'Send:{message!r}')
	writer.write(message.encode())

	data=await reader.read(100)
	print(f'Received:{data.decode()!r}')

	print('Closetheconnection')
	writer.close()

asyncio.run(tcp_echo_client(authorization_server,'Login request'))

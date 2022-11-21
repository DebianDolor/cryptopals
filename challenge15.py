def unpadPKCS7(data):
	padbyte = data[-1]
	if padbyte > len(data):
		return "invalid"
	padding = data[padbyte:]
	if padding.count(padbyte) != padbyte:
		return "invalid"
	return data[:-padbyte]


def main():
	valid = [
	    b"ICE ICE BABY\x04\x04\x04\x04",
	    b"NICE ICE BABY\x03\x03\x03",
	]

	invalid = [
	    b"ICE ICE BABY\x05\x05\x05\x05",
	    b"ICE ICE BABY\x01\x02\x03\x04",
	]

	for buf in valid + invalid:
	    print(str(buf).ljust(31), "=>", unpadPKCS7(buf))

if __name__ == "__main__":
	main()

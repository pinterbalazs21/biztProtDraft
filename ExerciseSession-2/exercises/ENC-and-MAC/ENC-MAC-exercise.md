ENC-and-MAC protocol
====================

We define a secure channel protocol, called ENC-and-MAC, as follows:

Message format:

	+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
	|  Ver  | T |  Len  |      SQN      |       random IV        ...|
	+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
	|...            random IV           |                           |
	+---+---+---+---+---+---+---+---+---+                           +
	|                                                               |
	+                                                               +
	|                              Payload                          |
	+                                                               +
	|                                                               |
	+       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+
	|       |x80 x00 x00 x00 x00 x00 x00|                           |
	+---+---+---+---+---+---+---+---+---+            MAC         ...+
	|                                                               |
	+...             MAC                +---+---+---+---+---+---+---+
	|                                   |
	+---+---+---+---+---+---+---+---+---+

where
- Ver contains the protocol version encoded on 2 bytes (major and minor version numbers)
- T contains the message type encoded on 1 byte
- Len contains the (full) message length encoded on 2 bytes
- SQN contains the message sequence number encoded on 4 bytes
- IV is a random IV
- Payload is the message payload
- x80x00x00... is ISO-7816 padding
- MAC is a MAC value computed with HMAC using SHA-256 on the header fields (Ver, T, Len, SQN), the IV, and the encrypted Payload (and padding)
- and ( Payload | padding ) is encrypted with AES in CBC mode using the random IV. 

Sequence numbers are handled as usual: SQN must be greater than the last received sequence number at the reciever in order for the message to be accepted. In addition, the MAC should verify successfully before decryption and the padding should be correct after decryption for accepting the message. 

We provided the program of the sender (`send.py`) in the handout folder. Your task is to complete the program of the receiver (`receive.py`). You should also copy and use the files `sndstate.txt` and `rcvstate.txt` that store the sending and receiving states, respectively. For testing purposes, we also provided a sample payload in `payload.txt`.

Once you finished your receiver program, try sending and receiving messages. Observe the output of your receiver program. Try also receieving the same message twice. Does your program detects the replay? Try modifying a valid message using a hex editor, and then receiving it with your receiver. What do you observe?



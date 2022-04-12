Using AES in GCM mode to implement a secure channel
===================================================

We want ot use the following message format in our protocol:

	+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
	|  Ver  | T |  Len  |      SQN      |            RND            |
	+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
	|                                                               |
	+                                                               +
	|                                                               |
	+                              Payload                          +
	|                            (encrypted)                        |
	+                                                               +
	|                                                               |
	+               +---+---+---+---+---+---+---+---+---+---+---+---+
	|               |                    AuthTag                    |
	+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+

where
- Ver contains the protocol version encoded on 2 bytes (major and minor version numbers)
- T contains the message type encoded on 1 byte
- Len contains the (full) message length encoded on 2 bytes
- SQN contains a message sequence number encoded on 4 bytes
- RND contains an 7-byte long random byte string
- Payload is the message payload encrypted with AES in GCM mode using SQN|RND as a nonce
- and AuthTag is the authentication tag produced by the GCM mode. 

Sequence numbers are handled as usual: SQN must be greater than the last received sequence number at the reciever in order for the message to be accepted. In addition, the entire message should verify successfully during GCM decoding. 

Complete the provided skeleton of the sender (`send.py`) and write your own receiver (`receive.py`). You should also copy and use the files `sndstate.txt` and `rcvstate.txt` that store the sending and receiving states, respectively. For testing purposes, we also provided a sample payload in `payload.txt`.




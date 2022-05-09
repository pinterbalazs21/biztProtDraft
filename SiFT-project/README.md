# Biztonsági Protokollok Homework - SiFT-protocol
## by thyme
### Zsófia Ádám/SOSK6A and Balázs Pintér/ZGY18G

### Usage
The project consists of a server and a client, which can be executed by running the `client.py` and `server.py` files with Python3 (we used Python 3.10.4).

The corresponding protocols are implemented under the server and client directories, so the server and the client can be packaged separately.
Please note that the code in the `common` directory should be added to both, as it contains helper and utility functions that both uses.

#### Set the Server address
To change the server IP address, `self.host` should be modified accordingly both in `client.py` and in `server.py`. The default value is `"localhost"`

#### Public Key
The public key should be in the root directory of the project as `public.key`.

#### Adding Users
Registering new users is not part of the protocol, so the required user base can be generated with the help of `registrationScript/generateUserData.py`. Add the required users and their passwords to the list in the script. It will generate the `../userdata.csv` file with the usernames, password hashes and salts, which then will be used by the server.

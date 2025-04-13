# HavocExternalC2
A PoC to working with Havoc ExternalC2. With communicate through Microsoft GraphAPI channel
Agent automatically get access token based on refresh token.
First. Create External C2 Listener
![image](https://github.com/user-attachments/assets/394ee4b8-215c-4876-91c6-98ae45c52aef)
Then run listener.py and handler.py
BOOM.
![image](https://github.com/user-attachments/assets/6784ff86-bb1b-4f89-8185-e7279382052c)
![image](https://github.com/user-attachments/assets/851c336c-52d2-430c-b783-59ecc950e9f6)

This is just a PoC to leverage graph.microsoft.com as a communicate channel.
The process of syncing is just scrap. The response maybe slow. And im not fully implement the command handler to handle the command. Example sometimes it does not have any output because the files is deleted

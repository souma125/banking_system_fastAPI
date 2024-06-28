1st step: Pull all the codes from git hub

2nd step: Please install the below packages.
pip install fastapi uvicorn sqlalchemy passlib bcrypt python-jose

3rd step: If you are facing any error related to bcrypt, please update the version of bcrypt.

4th step: Now start the server.
uvicorn main:app --reload

5th step: Open the swagger and test the APIs
http://127.0.0.1:8000/docs

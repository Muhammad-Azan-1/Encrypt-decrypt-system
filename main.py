import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import pathlib
import json
import time

stored_data = []
USER_FILE = pathlib.Path("./users.json")
LOCKOUT_DURATION = 60  # seconds

KEY_FILE = pathlib.Path("./secrect.key") # initally this file does not existss


#? creating a encryption and decrption key inside the secrect.key file
#? so if website runs again if statement runs and same KEY is used 
#? for  decryption that were used a the time of encryption
def load_or_create_key():
    if KEY_FILE.exists():
        return KEY_FILE.read_bytes()
    else:
        KEY = Fernet.generate_key() 
        KEY_FILE.write_bytes(KEY) # generates a symmetric encryption key — a random secret key used for both encrypting and decrypting data.
        return KEY
    
key = load_or_create_key()
cliper = Fernet(key) # creates a cipher object initialized with that key, which you use to encrypt and decrypt messages securely.



# Initialize session state

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

# failed_attempts = 0
# lockout_time = 0


#? create hash of password
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

#? encrypted the users data
def encrypted_data(text, pass_key):
    return cliper.encrypt(text.encode()).decode() , hash_passkey(pass_key)

#? decrypted the users data
def decrypted_data(text):
        return cliper.decrypt(text.encode()).decode()
   
# adding data to the json file


#? load previous data
def prev_data():
    try:
        with open(USER_FILE , 'r')  as f1:
            return json.load(f1)
    except Exception as e:
        print("ERROR",e)
        return []


#? add new  unique data/users  
def add_users(users_data):
   previuos_data = prev_data()
   usernames = {x['name'] for x in users_data}
   if previuos_data:
        for data in previuos_data:
            if data['name'] not in usernames:
                stored_data.append(data)

   with open(USER_FILE , 'w') as f:
        json.dump(users_data,f , indent=4)


menu = [ "login / register", "Home" , "Store Data" , "Retrieve Data"]

st.sidebar.title("Menu")
option = st.sidebar.selectbox("Options",menu)

def check_credentials(name: str, password: str):
    users_data = prev_data()
    for user in users_data:
        if user["name"] == name and user['data']["hash_pass"] == hash_passkey(password):
            return True
    return False



# def check_credentials(name:str , password:str): #? to check credentials first we need to load data from json file
#     users_data = prev_data()
#     for user_credentials in users_data:
#         if(user_credentials["name"] == name and user_credentials['data']["hash_pass"] == hash_passkey(password)):
#             return True
#     else:
#         st.error("Invalid credentials, you username or password is incorrect if you are new please register first")
#         return False

def register_new_user(name , password):
    users_data = prev_data()
    for user in users_data:
        if(user["name"] == name or user['data']["hash_pass"] == hash_passkey(password)):
            return False
    else:
        return True


#? login
if option == 'login / register':

    with st.container():
        st.markdown("<div class='box'>", unsafe_allow_html=True)
        st.markdown("<h1 style='text-align:center; font-size:30px;'>🔒 Secure Data Encryption System -  login Portal</h1>" , unsafe_allow_html=True)

    with st.form("login_form"):
        name = st.text_input("Enter Your Name")
        password = st.text_input("Enter Your Passowrd", type="password")
        login_btn =  st.form_submit_button("login")
        st.markdown("</div>", unsafe_allow_html=True)
        if login_btn:
            if check_credentials(name,password):
                st.success(f"Welcome {name}")
            else:
                st.error("Please register first")
           
               

    #? regiteration form
    with st.container():
        st.markdown("<div class='box'>", unsafe_allow_html=True)
        st.markdown("<h1 style='text-align:center; font-size:30px;'>📚 🔒 Secure Data Encryption System -  Registration Portal</h1>" , unsafe_allow_html=True)

    with st.form("Register_form"):
        name = st.text_input("Enter Your Name")
        password = st.text_input("Enter Your Passowrd", type="password")
        regis_btn =  st.form_submit_button("register")
        st.markdown("</div>", unsafe_allow_html=True)
        if regis_btn:
            if register_new_user(name , password):
                st.success(f"You have successfully register {name}")
                stored_data.append({"name":name , "data":{"encrypted_text": None , "hash_pass" : hash_passkey(password) }})
                add_users(stored_data)

            else:
                st.error(f"The user name {name} is already taken")




#? Home
elif option == "Home":
    st.title("🔒 Secure Data Encryption System")
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")




#? store Data
elif option == "Store Data":
    st.title("🔒 Secure Data Encryption System")
    st.subheader("Store your data it will be secured")
    user_name = st.text_input("Please enter your name")
    user_data =  st.text_area("Enter Data")
    user_pass =  st.text_input("Enter Passkey" , type="password")
    if st.button("Encrypt & save"):
        if user_name and user_data and user_pass:
            for val in prev_data():
                if user_name == val['name'] and hash_passkey(user_pass) == val['data']['hash_pass']:
                    user_encrypted_data , user_hash_pass = encrypted_data(user_data , user_pass)
                    stored_data.append({"name":user_name , "data":{"encrypted_text": user_encrypted_data , "hash_pass" : user_hash_pass }})
                    add_users(stored_data)
                    # print(stored_data)
                    st.success(f"Your data is successfully encrypted")
                    break
            else:
                st.error("Please enter a valid user name or pass key")
        else:
            st.error(f"All fields are required")



#? Retreive data
elif option == 'Retrieve Data':
      st.title("🔒 Secure Data Encryption System")
      st.subheader("Retrieve your data")
      name = st.text_input("Enter your name")
      password =  st.text_input("Enter your pass key" , type="password")

    #*---
      current_time = time.time()
      if st.session_state.failed_attempts == 3:
          time_left = int(st.session_state.lockout_time - current_time) #  1717000060 -  1717000000 = 60
          if time_left > 0:
                st.error(f"🔒 Locked out. Try again in {time_left} seconds.")
          else:
           st.session_state.failed_attempts = 0  # Reset after lockout
           lockout_time = 0


    #*---
      if st.session_state.failed_attempts < 3:
        if st.button("Decrypte"):
            if name and password:
                for val in prev_data():
                    if name == val['name'] and hash_passkey(password) == val['data']['hash_pass']:
                        st.success("Your data is decrypted")
                        st.success(decrypted_data(val['data']['encrypted_text']))
                        st.session_state.failed_attempts = 0
                        break
                else:
                    st.session_state.failed_attempts += 1
                    if st.session_state.failed_attempts == 3:
                            st.session_state.lockout_time = time.time() + LOCKOUT_DURATION # time.time() gives time in seconds since Jan 1, 1970 
                    st.error("Incorrect user name or password")                            # which is 1717001234.56 and we add 60 to it so now
            else:                                                                              # lockout_time = 1717000000 + 60 → 171700006 
                st.error("All fields are required")



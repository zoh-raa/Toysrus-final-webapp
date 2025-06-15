class User:
    count_id = 0

    def __init__(self, first_name, last_name, email, password, contact_number, address):
        User.count_id += 1
        self.__user_id = User.count_id
        self.__first_name = first_name
        self.__last_name = last_name
        self.__email = email
        self.__password = password
        self.__contact_number = contact_number
        self.__address = address

    def get_user_id(self):
        return self.__user_id

    def get_first_name(self):
        return self.__first_name

    def get_last_name(self):
        return self.__last_name

    def get_email(self):
        return self.__email

    def get_password(self):
        return self.__password

    def get_contact_number(self):
        return self.__contact_number

    def get_address(self):
        return self.__address

    def set_user_id(self):
        self.__user_id = User.count_id

    def set_first_name(self, first_name):
        self.__first_name = first_name

    def set_last_name(self, last_name):
        self.__last_name = last_name

    def set_email(self, email):
        self.__email = email

    def set_password(self, password):
        self.__password = password

    def set_contact_number(self, contact_number):
        self.__contact_number = contact_number

    def set_address(self, address):
        self.__address = address



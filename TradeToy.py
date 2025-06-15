import os

class TradeToy:
    count_id = 0

    def __init__(self, name, price, remarks, user_name='asaprocky', image="static\\tradetoysimages\\bear.png"):
        self.__name = name
        self.__price = price
        self.__remarks = remarks
        TradeToy.count_id += 1
        self.__count_id = TradeToy.count_id
        self.__user_name = user_name
        self.__image = image.replace(os.sep, '/') if image else image
        self.__offers = []  # To store the offers for this toy

    # Getter methods
    def get_name(self):
        return self.__name

    def get_price(self):
        return self.__price

    def get_remarks(self):
        return self.__remarks

    def get_user_name(self):
        return self.__user_name

    def get_id(self):
        return self.__count_id

    def get_image(self):
        return self.__image  # Returns the relative path like 'tradetoysimages/toy_image.jpg'


    # Setter methods
    def set_name(self, name):
        self.__name = name

    def set_price(self, price):
        self.__price = price

    def set_remarks(self, remarks):
        self.__remarks = remarks

    def set_image(self, image):
        self.__image = image.replace(os.sep, '/') if image else image


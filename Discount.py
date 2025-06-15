class Discount():
    count_id = 0

    # initializer method
    def __init__(self, name, percentage, startdate, enddate):

        Discount.count_id += 1
        self.__discount_id = Discount.count_id
        self.__name = name
        self.__percentage = percentage
        self.__startdate = startdate
        self.__enddate = enddate
        self.__redeemed_by = set()  #Used to track redeemed customers

    # accessor methods
    def get_discount_id(self):
        return self.__discount_id

    def get_name(self):
        return self.__name

    def get_percentage(self):
        return self.__percentage

    def get_startdate(self):
        return self.__startdate

    def get_enddate(self):
        return self.__enddate

    def get_redeemed_by(self):
        return self.__redeemed_by

    # mutator methods
    def set_discount_id(self, discount_id):
        self.__discount_id = discount_id

    def set_name(self, name):
        self.__name = name

    def set_percentage(self, percentage):
        self.__percentage = percentage

    def set_startdate(self, startdate):
        self.__startdate = startdate

    def set_enddate(self, enddate):
        self.__enddate = enddate

    def add_redeemed_customer(self, customer_id):
        self.__redeemed_by.add(customer_id)

    def remove_redeemed_customer(self, customer_id):
        self.__redeemed_by.discard(customer_id)

    def has_customer_redeemed(self, customer_id):
        return customer_id in self.__redeemed_by


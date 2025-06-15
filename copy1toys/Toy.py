
class Toy:
    count_id = 0

    def __init__(self, name, description, price, category, image,quantity=1):
        Toy.count_id += 1
        self.__toy_id = Toy.count_id
        self.__name = name
        self.__description = description
        self.__price = price
        self.__category = category
        self.__image = image
        self.__quantity = quantity  # ✅ New attribute

    # Accessor methods (getters)
    def get_toy_id(self):
        return self.__toy_id

    def get_name(self):
        return self.__name

    def get_description(self):
        return self.__description

    def get_price(self):
        return self.__price

    def get_category(self):
        return self.__category

    def get_image(self):
        return self.__image

    # Mutator methods (setters)
    def set_name(self, name):
        self.__name = name

    def set_description(self, description):
        self.__description = description

    def set_price(self, price):
        if price >= 0:  # Optional: Adding validation to ensure price is non-negative
            self.__price = price
        else:
            raise ValueError("Price must be non-negative")

    def set_category(self, category):
        self.__category = category

    def set_image(self, image):
        self.__image = image

    def get_quantity(self):
        """Ensure existing toys without quantity don't break the system"""
        if not hasattr(self, '_Toy__quantity'):  # ✅ Check if quantity exists
            self.__quantity = 1  # ✅ Set default quantity for old toys
        return self.__quantity

    def set_quantity(self, quantity):
        self.__quantity = quantity  # ✅ Setter for quantity

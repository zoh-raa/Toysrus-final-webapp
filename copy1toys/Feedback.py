from datetime import date
from User import User  # ✅ Import User class

class Feedback:
    count = 0

    def __init__(self, user: User, satisfactory, improvements, feedback_id=None, date_posted=None):
        """Initialize a feedback instance with a User object and auto-generated date."""
        Feedback.count += 1
        self.__feedback_id = feedback_id if feedback_id else Feedback.count
        self.__user = user  # ✅ Store the User instance
        self.satisfactory = satisfactory
        self.improvements = improvements
        self.date_posted = date_posted if date_posted else date.today()  # ✅ Auto-store today's date

    def get_feedback_id(self):
        return self.__feedback_id

    def get_user_id(self):
        """Get the user ID from the associated User instance."""
        return self.__user.get_user_id()

    def get_first_name(self):
        """Get the first name from the associated User instance."""
        return self.__user.get_first_name()

    def get_last_name(self):
        """Get the last name from the associated User instance."""
        return self.__user.get_last_name()

    def get_email(self):
        """Get the email from the associated User instance."""
        return self.__user.get_email()

    def get_satisfactory(self):
        return self.satisfactory

    def get_improvements(self):
        return self.improvements

    def get_date_posted(self):
        """✅ Getter method for the stored feedback date."""
        return self.date_posted

    def set_satisfactory(self, satisfactory):
        self.satisfactory = satisfactory

    def set_improvements(self, improvements):
        self.improvements = improvements

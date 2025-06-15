import re
import nltk
import datetime
from collections import Counter
from nltk.corpus import stopwords
from User import User  # ✅ Import User class
from Toy import Toy  # ✅ Import Toy class

# Download necessary resources (only needed once)
nltk.download('stopwords')

class qna:
    global_tags = []  # ✅ Stores most common keywords from Q&A

    STOPWORDS = set(stopwords.words('english'))  # Load stopwords
    MEANINGLESS_WORDS = {
        'very', 'really', 'just', 'also', 'even', 'quite', 'pretty', 'always', 
        'never', 'some', 'all', 'most', 'much', 'such', 'too', 'of', 'in', 
        'for', 'the', 'and', 'to', 'with', 'a', 'is', 'are', 'was', 'were', 
        'that', 'it', 'this', 'be', 'been', 'being'
    }
    count_id = 0

    @classmethod
    def get_global_tags(cls):
        return cls.global_tags

    def __init__(self, user: User, toy_id , qna_id, question, date_published):
        qna.count_id += 1
        self.__qna_id = qna.count_id
        self.__user = user  # ✅ User object
        self.__toy_id = toy_id  #  # ✅ Toy object
        self.__question = question  # ✅ The question text
        self.__date_published = date_published  # ✅ Auto-set to today's date
        self.answers = [] 
    # Getters
    def get_qna_id(self):
        return self.__qna_id

    def add_answer(self, user_id, answer_text, date):
        """✅ Adds an answer to the QnA entry."""
        self.answers.append({"user_id": user_id, "answer": answer_text, "date": date})

    def get_answers(self):
        return self.answers  # Ensure `self.answers` is a list



    def get_toy_id(self):
        return self.__toy_id  # ✅ Returns linked toy ID

    def get_question(self):
        return self.__question

    def get_date_published(self):
        return self.__date_published  # ✅ Return date_published

    def get_user_id(self):
        return self.__user.get_user_id()  # ✅ Returns user ID from User class

    def get_first_name(self):
        return self.__user.get_first_name()  # ✅ Returns user's first name

    def get_last_name(self):
        return self.__user.get_last_name()  # ✅ Returns user's last name

    # Setters
    def set_question(self, question):
        self.__question = question

    def set_qna_id(self, qna_id):
        self.__qna_id = qna_id


    @staticmethod
    def is_valid_word(word):
        """
        ✅ Ensures the word is at least 4 letters, alphabetical, and not a common meaningless word.
        """
        return (
            len(word) > 3 and 
            word.isalpha() and 
            word not in qna.STOPWORDS and 
            word not in qna.MEANINGLESS_WORDS
        )

    @staticmethod
    def extract_keywords(text):
        """
        ✅ Extracts meaningful words from a question.
        ✅ Removes punctuation and converts text to lowercase.
        """
        words = re.findall(r'\b[a-zA-Z]{4,}\b', text.lower())  # Finds words with at least 4 letters
        filtered_words = [word for word in words if qna.is_valid_word(word)]
        print(f"DEBUG: Extracted Keywords from Question -> {filtered_words}")  # ✅ Debugging
        return filtered_words

    @classmethod
    def update_global_tags(cls, qna_list):
        """
        ✅ Updates the most common keywords from all questions.
        """
        word_count = Counter()
        for qna in qna_list:
            keywords = cls.extract_keywords(qna.get_question())
            word_count.update(keywords)

        cls.global_tags = [word for word, count in word_count.most_common(10)]
        print(f"DEBUG: Updated Global QnA Tags -> {cls.global_tags}")  # ✅ Debugging

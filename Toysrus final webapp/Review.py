import re
import nltk
from collections import Counter
from nltk.corpus import stopwords, words  # ✅ Import words properly

from User import User  # ✅ Keep your User import

nltk.download('words')  # ✅ Download the words corpus
nltk.download('stopwords')  # ✅ Ensure stopwords are downloaded

VALID_WORDS = set(words.words())  # ✅ Load valid English words

class Review:
    global_tags = []  # ✅ Stores most common words across all reviews

    STOPWORDS = set(stopwords.words('english'))  # Load stopwords
    MEANINGLESS_WORDS = {
        'very', 'really', 'just', 'also', 'even', 'quite', 'pretty', 'always', 
        'never', 'some', 'all', 'most', 'much', 'such', 'too', 'of', 'in', 
        'for', 'the', 'and', 'to', 'with', 'a', 'is', 'are', 'was', 'were', 
        'that', 'it', 'this', 'be', 'been', 'being'
    }

    # ✅ Corrected reference to words.words()
    VALID_WORDS = set(words.words())



    @classmethod
    def get_global_tags(cls):
        return cls.global_tags

    
    def __init__(self, user: User, rating, comment, date, review_id, toy_id, image_path=None):
        self.__user = user
        self.__rating = rating
        self.__comment = comment
        self.__date = date
        self.__review_id = review_id
        self.__toy_id = toy_id  # Only storing toy_id, not full Toy object
        self.__image_path = image_path  # Optional image path
        self.__likes = 0  # Initialize likes counter
        self.liked_users = set()  # Track users who liked this review

    def like_review(self, user_id):
        """Add a like if the user hasn't liked it before."""
        if user_id not in self.liked_users:
            self.liked_users.add(user_id)
            self.__likes += 1
            return True
        return False  # User already liked

    def unlike_review(self, user_id):
        """Remove a like if the user has already liked it."""
        if user_id in self.liked_users:
            self.liked_users.remove(user_id)
            self.__likes -= 1
            return True
        return False  # User didn't like before

    def get_likes(self):
        """Getter for likes count."""
        return self.__likes

    # Getters
    def get_user_id(self):
        return self.__user.get_user_id()

    def get_user_email(self):
        return self.__user.get_email()

    def get_review_id(self):
        return self.__review_id

    def get_rating(self):
        return self.__rating

    def get_comment(self):
        return self.__comment

    def get_date(self):
        return self.__date

    def get_toy_id(self):
        return self.__toy_id  # ✅ Returns linked toy ID

    def get_image_url(self):
        return self.__image_path  

    # Setters
    def set_review_id(self, review_id):
        self.__review_id = review_id

    def set_rating(self, rating):
        self.__rating = rating

    def set_comment(self, comment):
        self.__comment = comment

    @staticmethod
    def is_valid_word(word):
        """
        ✅ Ensures the word is at least 6 letters, alphabetical, meaningful, and not gibberish.
        """
        return (
            len(word) > 4 and  # ✅ Require words to be longer than 5 letters
            word.isalpha() and 
            word not in Review.STOPWORDS and 
            word not in Review.MEANINGLESS_WORDS and 
            word in Review.VALID_WORDS and  # ✅ Ensure word exists in the dictionary
            not re.search(r"(.)\1{3,}", word)  # ✅ Filter out excessive repeated letters (e.g., "looooool")
        )

    @staticmethod
    def extract_keywords(text):
        """
        ✅ Extracts meaningful words from a review comment.
        ✅ Removes punctuation and converts text to lowercase.
        """
        words = re.findall(r'\b[a-zA-Z]{6,}\b', text.lower())  # ✅ Finds words with at least 6 letters
        filtered_words = [word for word in words if Review.is_valid_word(word)]
        print(f"DEBUG: Extracted Keywords from Review -> {filtered_words}")  # ✅ Debugging
        return filtered_words

    @classmethod
    def update_global_tags(cls, reviews):
        """
        ✅ Updates the most common keywords from all reviews.
        """
        word_count = Counter()
        for review in reviews:
            keywords = cls.extract_keywords(review.get_comment())
            word_count.update(keywords)

        cls.global_tags = [word for word, count in word_count.most_common(10)]  # ✅ Keep only the top 10 most frequent words

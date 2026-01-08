# User authentication to access web UI restricted views (i.e. whitelisting, dashboard, updating of signatures, etc.)
# Lots of documentation on Flask-Login User Class for SQLAlchemy, very little for MongoDB...
# Hence did not follow Flask-Login official documentation, made a very simple UserAccount class based on our use case

class UserAccount:
    def __init__(self, username):
        self.username = username
        self.password = None
        self.admin = False
        self.api_key_info = None

    @staticmethod
    def is_authenticated():
        return True

    @staticmethod
    def is_active():
        return True

    @staticmethod
    def is_anonymous():
        return False
    
    # To add admin privileges to specified user
    def add_admin_power(self): # If is_admin is True in MongoDB, then this function will be invoked by another function.
        self.admin = True

    # To check if specified user possesses admin privileges
    def is_admin(self):
        return self.admin

    # To add API key information to specified user (if user has an existing key)    
    def add_api_key_info(self, api_key_info):
        self.api_key_info = api_key_info
    
    # To fetch information about user's API key (returns None if none, and dict if user has an existing key)    
    def get_api_key_info(self):
        return self.api_key_info

    # To fetch user's ID (username)
    def get_id(self): # in this case, use username as id (username has been set to be unique in MongoDB database)
        return self.username 
    
    def json(self):
        return {"username": self.username, "password": self.password}
        
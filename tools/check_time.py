import time

def check_time(times, home, argstimes):
    if (times - home) >= argstimes:
        print("Limit time reached. Your user will be disconected now")
        return True




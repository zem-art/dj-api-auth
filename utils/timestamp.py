import time

def get_timestamp_milliseconds():
    """
    Mengambil timestamp saat ini dalam milidetik.

    Returns:
    - int: Timestamp dalam milidetik.
    """
    return int(time.time() * 1000)

# # Contoh penggunaan
# timestamp_milliseconds = get_timestamp_milliseconds()
# print("Timestamp dalam milidetik:", timestamp_milliseconds)
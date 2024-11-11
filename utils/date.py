from datetime import datetime

def convert_datetime_format(date_str):
    try:
        # Mengonversi string tanggal sesuai format yang diinginkan
        return datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S.%fZ").strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        # Menangani error jika format date_str tidak sesuai
        return None

from rest_framework.response import Response
from rest_framework import status

def create_custom_response(title:str, message:str, data:any=None, error:any=None, status_code:int=status.HTTP_200_OK):
    return Response({
        'title': title,
        'message': message,
        'error': error,
        'status_code': status_code,
        'data': data or {}
    }, status=status_code)
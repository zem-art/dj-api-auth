from rest_framework.pagination import PageNumberPagination

class CustomPageNumberPagination(PageNumberPagination):
    """
        NOTE :
        - page : to select a page.
        - page_size : to determine the number of items per page.
    """
    page = 1
    page_size = 5
    page_size_query_param = 'page_size'
    max_page_size = 100
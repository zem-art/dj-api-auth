import os
import firebase_admin
from firebase_admin import credentials, initialize_app, storage
from django.conf import settings

class FirebaseImageUploader:
    def __init__(self):
        cred = credentials.Certificate(settings.FIREBASE_ADMIN_CERT)
        if not len(firebase_admin._apps):
            initialize_app(cred, {'storageBucket': settings.FIREBASE_STORAGE_BUCKET})
        self.bucket = storage.bucket()

    def upload_image(self, image_file, destination_path):
        blob = self.bucket.blob(destination_path)
        blob.upload_from_file(image_file, content_type='image/jpeg')
        blob.make_public()
        return blob.public_url

    def delete_image(self, image_path):
        blob = self.bucket.blob(image_path)
        blob.delete()

    def get_image_url(self, image_path):
        blob = self.bucket.blob(image_path)
        blob.make_public()
        return blob.public_url
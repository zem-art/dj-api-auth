from django.db import models

# Create your models here.

class TodoModel(models.Model):

    uid = models.CharField(max_length=25,unique=True)
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    completed = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    deleted_flag = models.BooleanField(default=False, blank=True, null=True)
    deleted_at = models.DateTimeField(blank=True, null=True)

    def __str__(self):
        return self.title
    

class ImageTodoModel(models.Model):

    uid = models.CharField(max_length=25,unique=True)
    uid_todo = models.CharField(max_length=25, blank=True, null=True)
    todo_id = models.ForeignKey(TodoModel, related_name='todo_model', on_delete=models.CASCADE)
    link_image_todo = models.TextField(blank=True, null=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return "{}-{}".format(self.id , self.uid)
from django.contrib.auth.models import Group, User
from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken
from .models import TodoModel
from utils.random import generate_random_string
from utils.timestamp import get_timestamp_milliseconds


class UserSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = User
        fields = [
            'id', 'username', 'email',
            'first_name', 'last_name', 'is_staff', 
            'is_superuser', 'is_active', 'date_joined',
        ]


class GroupSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Group
        fields = ['id', 'name']

      
class UserSerializateRegister(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    class Meta:
        model=User
        fields= (
            'username', 'email', 'first_name', 
            'last_name', 'password'
        )
        
    def create(self, validated_data):
        user = User(
            username=validated_data['username'],
            email=validated_data.get('email', ''),
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', '')
        )
        user.set_password(validated_data['password'])
        user.save()
        return user


class TodoSerializate(serializers.ModelSerializer):

    class Meta:
        model = TodoModel
        fields = [
            'uid', 'title', 'description', 
            'completed', 'created_at', 'updated_at',
            'id',
        ]

    uid = serializers.CharField(read_only=True)
    """
    - read_only=True: uid can only be filled in during object creation (POST),
        and cannot be changed during updates (PUT or PATCH).
    """

    def create(self, validated_data):
        """
        Note
        - ways to store data in a serializer in Django, but there are some better or more commonly used approaches in the Django REST Framework.
        - Override default for 'uid' to be generated only on creation
        - If 'uid' is not in validated_data, then generate
        """

        ## data manipulation before saving
        if 'uid' not in validated_data:
            validated_data['uid'] = f"{generate_random_string(5)}{get_timestamp_milliseconds()}"

        ## how to 1
        todo_instance = TodoModel.objects.create(**validated_data)

        ## how to 2
        # data_todo = TodoModel(
        #     uid = validated_data.get('uid'),
        #     title = validated_data.get('title'),
        #     description = validated_data.get('description'),
        #     completed = validated_data.get('completed'),
        #     created_at = validated_data.get('created_at'),
        #     updated_at = validated_data.get('updated_at'),
        # )
        # todo_instance.save()
        return todo_instance
    
    def update(self, instance, validated_data):
        # Jika 'uid' tidak disertakan dalam data update, biarkan 'uid' tetap sama
        # Anda bisa menambahkan logika khusus jika perlu memodifikasi 'uid' saat update
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance

from rest_framework import serializers
from .models import User,Organisation

class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ['userId','firstName','lastName','email','phone']

class OrgSerializer(serializers.ModelSerializer):
    class Meta:
        model = Organisation
        fields = ['orgId', 'name', 'description']
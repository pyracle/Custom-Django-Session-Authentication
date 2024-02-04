from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers
from .models import User, PasswordResetToken


class AbstractUserSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(max_length=100)

    class Meta:
        model = User
        fields = ["username", "first_name", "last_name", "email", "password", "confirm_password"]

    def validate(self, data: dict):
        password = data["password"]
        if password != data["confirm_password"]:
            raise serializers.ValidationError("Passwords don't match.")
        try:
            validate_password(password)
        except ValidationError:
            raise serializers.ValidationError("Password is too weak.")
        return data


class CreateUserSerializer(AbstractUserSerializer):
    confirm_password = serializers.CharField(max_length=100)

    def create(self, validated_data: dict):
        validated_data = {field: validated_data.get(field) for field in self.Meta.fields[:5]}
        return self.Meta.model.objects.create_user(**validated_data)

    def validate(self, data: dict):
        if not data.get("first_name") or not data.get("last_name"):
            raise serializers.ValidationError("Please enter your first and last name.")
        return super().validate(data)


class UpdateUserSerializer(AbstractUserSerializer):
    def update(self, instance, validated_data: dict):
        instance.set_password(
            validated_data.get("password", instance.password)
        )
        instance.save()
        return instance


class CreatePasswordResetTokenSerializer(serializers.ModelSerializer):
    class Meta:
        model = PasswordResetToken
        fields = ["token", "user"]

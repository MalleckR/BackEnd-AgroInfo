from rest_framework import serializers
from django.contrib.auth import get_user_model
from agroinfo_app.models import Property, Plantio, Historico

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'cep', 'sobrenome', 'cidade', 'estado', 'datadenascimento', 'ativo', 'created_at']
        extra_kwargs = {
            'created_at': {'read_only': True}  # Garante que created_at seja apenas para leitura
        }

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user

class PropertySerializer(serializers.ModelSerializer):
    class Meta:
        model = Property
        fields = ['id', 'owner', 'endereco', 'distritooulocalidade', 'numero', 'cidade', 'created_at']

class PlantioSerializer(serializers.ModelSerializer):
    class Meta:
        model = Plantio
        fields = '__all__'

class HistoricoSerializer(serializers.ModelSerializer):
    class Meta:
        model = Historico
        fields = '__all__'
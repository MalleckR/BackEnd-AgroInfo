from django.contrib.auth.models import AbstractUser
from django.db import models
from django.contrib.auth import get_user_model

class CustomUser(AbstractUser):
    cep = models.CharField(max_length=100)
    sobrenome = models.CharField(max_length=100)
    cidade = models.CharField(max_length=100)
    estado = models.CharField(max_length=100)
    datadenascimento = models.CharField(max_length=100)
    ativo = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

User = get_user_model()    

class Property(models.Model):
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    endereco = models.CharField(max_length=100)
    distritooulocalidade = models.CharField(max_length=100)
    numero = models.CharField(max_length=100)
    cidade = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)

class Plantio(models.Model):
    dimensao = models.CharField(max_length=100)
    tipodegraoplantado = models.CharField(max_length=100)
    localizacao = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)
    tokensensores = models.CharField(max_length=500)
    propriedade = models.ForeignKey('Property', on_delete=models.CASCADE, related_name='plantios')

    def __str__(self):
        return f"Plantio {self.id}"
    
class Historico(models.Model):
    usuario = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    data_hora = models.DateTimeField(auto_now_add=True)
    informacao = models.TextField()

    def __str__(self):
        return f'{self.data_hora} - {self.usuario.username if self.usuario else "Usuário Anônimo"}'


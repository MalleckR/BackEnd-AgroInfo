from rest_framework import status, generics, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import CustomUser, Property, Plantio, Historico  # Importe seu modelo personalizado
from .serializers import UserSerializer, PropertySerializer, PlantioSerializer, HistoricoSerializer
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate
from django.contrib.auth.models import AbstractBaseUser
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.contrib.auth import authenticate, get_user_model
from rest_framework.authentication import SessionAuthentication, BasicAuthentication
from rest_framework.permissions import AllowAny
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken
import paho.mqtt.client as paho
import datetime, time, json

from django.http import HttpResponse, StreamingHttpResponse, HttpResponseServerError
from agroinfo_app.mqtt_client import MqttClient
from django.views.decorators.http import require_http_methods
from django.views.generic import View
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.utils.http import http_date

MQTT_BROKER = '62b5c4db0ce64ecda89a0953c4c6c845.s1.eu.hivemq.cloud'
MQTT_PORT = 8883
MQTT_USERNAME = 'malleck'
MQTT_PASSWORD = '12345678'

mqtt_client = MqttClient(MQTT_BROKER, MQTT_PORT, MQTT_USERNAME, MQTT_PASSWORD)

#---------------------------------------------------------------------------------------------------------

#API's Relacionadas ao Usuario

class CreateUserView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        # Verificando se o usuário já existe no banco de dados
        username = request.data.get('username')
        if CustomUser.objects.filter(username=username).exists():  # Use CustomUser em vez de User
            return Response({'error': 'Este usuário já existe.'}, status=status.HTTP_400_BAD_REQUEST)

        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request):
        users = CustomUser.objects.all()  # Use CustomUser em vez de User
        serializer = UserSerializer(users, many=True)  # Serializa todos os usuários
        return Response(serializer.data, status=status.HTTP_200_OK)

class UpdateUserView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request):
        # Obtém o usuário autenticado
        user = request.user

        # Obtém os dados enviados na requisição
        data = request.data

        # Atualiza os dados do usuário com os dados enviados
        serializer = UserSerializer(user, data=data, partial=True)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
class DeleteUserView(APIView):
    User = get_user_model()
    permission_classes = [IsAuthenticated]

    def delete(self, request):
        # Obtém o usuário autenticado
        user = request.user

        # Exclui o usuário
        user.delete()

        return Response({'message': 'Usuário excluído com sucesso'}, status=status.HTTP_204_NO_CONTENT)

class LoginView(APIView):
    authentication_classes = []  # Remove outras classes de autenticação
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        # Autenticar o usuário
        user = authenticate(username=username, password=password)

        if user is not None:
            refresh = RefreshToken.for_user(user)
            return Response({'token': str(refresh.access_token)}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Credenciais inválidas'}, status=status.HTTP_401_UNAUTHORIZED)

class ChangePasswordView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        # Obtenha as credenciais do usuário
        username = request.data.get('username')
        old_password = request.data.get('old_password')
        new_password = request.data.get('new_password')

        # Autenticar o usuário
        user = authenticate(username=username, password=old_password)

        # Verificar se as credenciais são válidas
        if user is None:
            return Response({'error': 'Credenciais inválidas'}, status=status.HTTP_401_UNAUTHORIZED)

        # Verificar se a nova senha é diferente da antiga
        if old_password == new_password:
            return Response({'error': 'A nova senha não pode ser igual à antiga'}, status=status.HTTP_400_BAD_REQUEST)

        # Mudar a senha do usuário
        user.set_password(new_password)
        user.save()

        return Response({'message': 'Senha alterada com sucesso'}, status=status.HTTP_200_OK)
    
#---------------------------------------------------------------------------------------------------------

#API's Relacionadas a Propriedade

class PropertyCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = PropertySerializer(data=request.data)
        if serializer.is_valid():
            # Associar a propriedade ao usuário logado
            serializer.save(owner=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def get(self, request):
        property = Property.objects.all()  # Use CustomUser em vez de User
        serializer = PropertySerializer(property, many=True)  # Serializa todos os usuários
        return Response(serializer.data, status=status.HTTP_200_OK)
    
class UpdatePropertyView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request, pk):
        # Obtém a propriedade a ser editada
        try:
            property = Property.objects.get(pk=pk)
        except Property.DoesNotExist:
            return Response({'error': 'Propriedade não encontrada'}, status=status.HTTP_404_NOT_FOUND)

        # Verifica se o usuário logado é o proprietário da propriedade
        if request.user != property.owner:
            return Response({'error': 'Você não tem permissão para editar esta propriedade'}, status=status.HTTP_403_FORBIDDEN)

        # Obtém os dados enviados na requisição
        data = request.data

        # Atualiza os dados da propriedade com os dados enviados
        serializer = PropertySerializer(property, data=data, partial=True)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
class DeletePropertyView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, pk):
        # Verifica se a propriedade existe
        try:
            property = Property.objects.get(pk=pk)
        except Property.DoesNotExist:
            return Response({'error': 'A propriedade não existe'}, status=status.HTTP_404_NOT_FOUND)
        
        # Verifica se o usuário é o proprietário da propriedade
        if property.owner != request.user:
            return Response({'error': 'Você não tem permissão para excluir esta propriedade'}, status=status.HTTP_403_FORBIDDEN)
        
        # Exclui a propriedade
        property.delete()
        return Response({'message': 'Propriedade excluída com sucesso'}, status=status.HTTP_204_NO_CONTENT)
    
class ListUserProperties(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        properties = Property.objects.filter(owner=user)
        serializer = PropertySerializer(properties, many=True)
        return Response(serializer.data)
    
#---------------------------------------------------------------------------------------------------------

#API's Relacionadas a Plantio

class PlantioListCreateAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = PlantioSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(propriedade=request.user.property_set.get(id=request.data['propriedade']))
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


    def get(self, request):
        plantios = Plantio.objects.all()
        serializer = PlantioSerializer(plantios, many=True)
        return Response(serializer.data)
    
class UpdatePlantioView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request, pk):
        try:
            plantio = Plantio.objects.get(pk=pk)
        except Plantio.DoesNotExist:
            return Response({"error": "Plantio não encontrado"}, status=status.HTTP_404_NOT_FOUND)

        # Verifica se o usuário tem permissão para editar este plantio
        if plantio.propriedade.owner != request.user:
            return Response({"error": "Você não tem permissão para editar este plantio"}, status=status.HTTP_403_FORBIDDEN)

        serializer = PlantioSerializer(plantio, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class DeletePlantioView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, pk):
        try:
            plantio = Plantio.objects.get(pk=pk)
        except Plantio.DoesNotExist:
            return Response({'error': 'Plantio não encontrado'}, status=status.HTTP_404_NOT_FOUND)

        # Verificar se o usuário tem permissão para excluir o plantio
        if plantio.propriedade.owner != request.user:
            return Response({'error': 'Você não tem permissão para excluir este plantio'}, status=status.HTTP_403_FORBIDDEN)

        # Excluir o plantio
        plantio.delete()
        return Response({'message': 'Plantio excluído com sucesso'}, status=status.HTTP_204_NO_CONTENT)
    
class ListPlantioIDsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Filtrar os IDs dos plantios do usuário autenticado
        plantios = Plantio.objects.filter(propriedade__owner=request.user)
        plantio_ids = [plantio.id for plantio in plantios]
        
        # Retornar os IDs dos plantios
        return Response({'plantio_ids': plantio_ids})
    
#---------------------------------------------------------------------------------------------------------

#API's Relacionadas com a Visualização de dados

class HistoricoUsuarioAPIView(generics.ListAPIView):
    serializer_class = HistoricoSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        # Retorna o histórico do usuário autenticado
        return Historico.objects.filter(usuario=self.request.user)

class SensorDataView(APIView):
    permission_classes = [IsAuthenticated]
    
    # Função chamada quando uma mensagem é recebida
    def on_message(self, client, userdata, msg):
        payload = msg.payload.decode("utf-8")
        # Salvar a mensagem no atributo 'informacoes' do modelo Historico
        user = self.request.user
        Historico.objects.create(informacao=payload, usuario=user)
        print(msg.topic + " " + str(msg.qos) + " " + payload)

    # Função chamada quando a conexão é estabelecida
    def on_connect(self, client, userdata, flags, rc, properties=None):
        print("CONNACK received with code %s." % rc)
        plantio_token = userdata['plantio_token']
        client.subscribe(plantio_token, qos=1)

    # Função chamada quando a subscrição é realizada
    def on_subscribe(self, client, userdata, mid, granted_qos, properties=None):
        print("")
        print("Subscribed: " + str(mid) + " " + str(granted_qos))

    def get(self, request, plantio_id):
        # Obter o objeto Plantio pelo ID
        try:
            plantio = Plantio.objects.get(id=plantio_id)
        except Plantio.DoesNotExist:
            return Response({"detail": "O Plantio não existe."}, status=400)

        # Obter o token de sensores do Plantio
        plantio_token = plantio.tokensensores

        # Configurar o cliente MQTT
        client = paho.Client(client_id="", userdata={'plantio_token': plantio_token}, protocol=paho.MQTTv5)
        client.on_message = self.on_message
        client.on_connect = self.on_connect
        client.on_subscribe = self.on_subscribe
        
        # Configurações adicionais do cliente MQTT (TLS, usuário, senha, conexão)
        client.tls_set(tls_version=paho.ssl.PROTOCOL_TLS)
        client.username_pw_set("malleck", "12345678")
        client.connect("62b5c4db0ce64ecda89a0953c4c6c845.s1.eu.hivemq.cloud", 8883)
        
        # Conectar ao tópico MQTT do Plantio
        client.subscribe(plantio_token, qos=1)

        # Iniciar o loop de espera para manter o programa em execução e processar mensagens
        client.loop_start()

        # Retorna uma resposta (neste caso, vazia)
        return Response({})

#Funcionando
#-----------------------------

class MqttSubscribeView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        topic = request.data.get('topic')
        if topic:
            mqtt_client.subscribe(topic)
            return Response({"status": f"Subscribed to topic {topic}"})
        return Response({"error": "No topic provided"}, status=400)

@method_decorator(csrf_exempt, name='dispatch')
class MqttStreamView(View):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            return self.stream_response()
        except Exception as e:
            return HttpResponseServerError(str(e))

    def stream_response(self):
        def event_stream():
            while True:
                message = mqtt_client.get_message()
                if message:
                    formatted_data = {"data": message}
                    yield f"data: {json.dumps(formatted_data)}\n\n"
                time.sleep(1)

        response = StreamingHttpResponse(event_stream(), content_type='text/event-stream')
        response['Cache-Control'] = 'no-cache'
        response['Access-Control-Allow-Origin'] = '*'
        response['Access-Control-Allow-Credentials'] = 'true'
        response['X-Accel-Buffering'] = 'no'
        return response
    
        
    

from django.urls import path
from .views import (
    LoginView,
    CreateUserView,
    ChangePasswordView,
    UpdateUserView,
    DeleteUserView,
    PropertyCreateView,
    UpdatePropertyView,
    DeletePropertyView,
    ListUserProperties,
    PlantioListCreateAPIView,
    UpdatePlantioView,
    DeletePlantioView,
    ListPlantioIDsView,
    HistoricoUsuarioAPIView,
    SensorDataView,
    MqttSubscribeView, 
    MqttStreamView
)


urlpatterns = [

    #URL Relacionado a Usuario

    path('login/', LoginView.as_view(), name='login'),
    path('create_user/', CreateUserView.as_view(), name='create_user'),
    path('change_password/', ChangePasswordView.as_view(), name='change_password'),
    path('update_user/', UpdateUserView.as_view(), name='update_user'),
    path('delete_user/', DeleteUserView.as_view(), name='delete_user'),

    #URL Relacionado a Propriedade

    path('create_property/', PropertyCreateView.as_view(), name='create_property'),
    path('update_property/<int:pk>/', UpdatePropertyView.as_view(), name='update_property'),
    path('delete_property/<int:pk>/', DeletePropertyView.as_view(), name='delete_property'),
    path('list_user_properties/', ListUserProperties.as_view(), name='list_user_properties'),

    #URL Relacionado a Plantio

    path('cadastrar_plantio/', PlantioListCreateAPIView.as_view(), name='cadastrar_plantio'),
    path('update_plantios/<int:pk>/', UpdatePlantioView.as_view(), name='update_plantio'),
    path('delete_plantios/<int:pk>/', DeletePlantioView.as_view(), name='delete_plantio'),
    path('list_plantios/ids/', ListPlantioIDsView.as_view(), name='list_plantio_ids'),
    
    #URL Relacionada a Visualização de dados

    path('historico_usuario/', HistoricoUsuarioAPIView.as_view(), name='historico-usuario'),
    path('visualizar_dados/<int:plantio_id>/', SensorDataView.as_view(), name='visualizar_dados'),
    path('mqtt/', MqttSubscribeView.as_view(), name='mqtt_subscribe'),
    path('mqtt/stream/', MqttStreamView.as_view(), name='mqtt_stream'),
    
]

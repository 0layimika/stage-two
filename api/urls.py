from django.urls import path
from .views import *

urlpatterns=[
    path('auth/register', RegisterView.as_view(), name='register'),
    path('auth/login', LoginView.as_view(),name='login'),
    path('api/users/<str:id>', UserView.as_view(), name='user-detail'),
    path('api/organisations', OrganisationsView.as_view(), name='user-org'),
    path('api/organisations/<str:id>', OrgView.as_view(), name='specific-org'),
    path('api/organisations/<str:id>/users', addOrgView.as_view(), name='specific-user-to-org'),
    path('',home, name='home')
]
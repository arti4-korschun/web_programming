from django.contrib.auth import views as auth_views
from django.urls import path
from . import views
from .views import check_username

urlpatterns = [
    # Страницы для работы с книгами
    path('', views.book_list, name='book_list'),
    path('new/', views.book_create, name='book_create'),
    path('<int:pk>/edit/', views.book_update, name='book_update'),
    path('<int:pk>/delete/', views.book_delete, name='book_delete'),

    # Страницы для регистрации и авторизации
    path('login/', views.login_user, name='login_user'),  # Путь для логина
    path('register/', views.register, name='register'),
    path('logout/', views.logout_user, name='logout_user'),

    # Стандартный путь для входа
    path('accounts/login/', auth_views.LoginView.as_view(template_name='books/login_user.html'), name='login'),
    path('check_username/', check_username, name='check_username'),
]

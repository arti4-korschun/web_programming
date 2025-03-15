from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth.decorators import user_passes_test
from django.core.paginator import Paginator
from django.utils import timezone
from .models import Book, User
from .forms import BookForm
from django.http import JsonResponse
import hashlib
import binascii

def book_list(request):
    user = None
    if is_authenticated(request):
        user_id = request.session.get('user_id')
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            pass

    # Получаем параметры сортировки и фильтрации
    sort_by = request.GET.get('sort_by', 'title')
    order = request.GET.get('order', 'asc')
    title_filter = request.GET.get('title', '')  # Фильтрация по названию
    author_filter = request.GET.get('author', '')  # Фильтрация по автору
    min_price = request.GET.get('min_price', '')  # Минимальная цена
    max_price = request.GET.get('max_price', '')  # Максимальная цена

    # Формируем условия для фильтрации
    books = Book.objects.all()

    if title_filter:
        books = books.filter(title__icontains=title_filter)
    if author_filter:
        books = books.filter(author__icontains=author_filter)
    if min_price:
        books = books.filter(price__gte=min_price)
    if max_price:
        books = books.filter(price__lte=max_price)

    # Сортировка
    if order == 'desc':
        order_by = '-' + sort_by
    else:
        order_by = sort_by
    books = books.order_by(order_by)

    paginator = Paginator(books, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    return render(request, 'books/book_list.html', {
        'page_obj': page_obj,
        'user': user,
        'sort_by': sort_by,
        'order': order,
        'title_filter': title_filter,
        'author_filter': author_filter,
        'min_price': min_price,
        'max_price': max_price,
    })

def book_create(request):
    if not is_authenticated(request):
        return redirect('login_user')
    # Защита от SQL-инъекций
    if request.method == "POST":
        form = BookForm(request.POST) # Запрос проходит валидацию
        if form.is_valid(): # Проверяет данные на соответствие правилам модели
            form.save() # Сохраняет данные через Django ORM, который автоматически предотвращает SQL-инъекции
            return redirect('/')
    else:
        form = BookForm()
    return render(request, 'books/book_form.html', {'form': form})

def book_update(request, pk):
    if not is_authenticated(request):
        return redirect('login_user')
    user_id = request.session.get('user_id')
    user = get_object_or_404(User, id=user_id)
    if not is_admin(user):
        return redirect('book_list')
    book = get_object_or_404(Book, pk=pk)
    if request.method == "POST":
        form = BookForm(request.POST, instance=book)
        if form.is_valid():
            form.save()
            return redirect('/')
    else:
        form = BookForm(instance=book)
    return render(request, 'books/book_form.html', {'form': form})

def book_delete(request, pk):
    if not is_authenticated(request):
        return redirect('login_user')  # Перенаправляем на страницу входа, если не аутентифицирован

    user_id = request.session.get('user_id')
    user = get_object_or_404(User, id=user_id)
    if not is_admin(user):
        return redirect('book_list')  # Если не администратор, перенаправляем на список книг

    book = get_object_or_404(Book, pk=pk)
    if request.method == "POST":
        book.delete()
        return redirect('/')
    return render(request, 'books/book_confirm_delete.html', {'book': book})


# Проверка на админа
def is_admin(user):
    return user.isAdmin

# Проверка на то, вошёл ли пользователь
def is_authenticated(request):
    user_id = request.session.get('user_id')
    return user_id is not None

# Функция для хэширования пароля
def hash_password(password):
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), b'', 100000)
    return binascii.hexlify(dk).decode()

# Функция для проверки пароля
def verify_password(password, hashed_password):
    return hash_password(password) == hashed_password

# Страница входа
def login_user(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = custom_authenticate(username, password)
        if user is not None:
            request.session['user_id'] = user.id  # Сохраняем ID пользователя в сессии
            login(request, user)  # Входим в систему
            return redirect('book_list')
        else:
            return render(request, 'books/login_user.html', {'error': 'Неверный логин или пароль'})

    return render(request, 'books/login_user.html')

# Аутентификация с проверкой хешированного пароля
def custom_authenticate(username, password):
    user = User.objects.filter(username=username).first()
    if user and verify_password(password, user.password):
        return user
    return None

# Страница регистрации
def register(request):
    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']
        name = request.POST['name']
        is_admin = 'isAdmin' in request.POST

        if User.objects.filter(username=username).exists():
            return render(request, 'books/register.html', {'error': 'Логин уже занят'})

        hashed_password = hash_password(password)  # Используем новую функцию
        user = User(username=username, password=hashed_password, email=email, name=name, isAdmin=is_admin)
        user.save()

        request.session['user_id'] = user.id
        login(request, user)
        return redirect('book_list')

    return render(request, 'books/register.html')

# Проверка данных
def check_username(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        user_exists = User.objects.filter(username=username).exists()
        return JsonResponse({'exists': user_exists})

# Выход из системы
def logout_user(request):
    logout(request)
    return redirect('/')
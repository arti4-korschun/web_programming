from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth.decorators import user_passes_test
from django.core.paginator import Paginator
from django.utils import timezone
from .models import Book, User
from .forms import BookForm
from django.http import JsonResponse

# Проверка на админа (для ограниченного доступа)
def is_admin(user):
    return user.isAdmin

# Страница списка книг (доступна всем пользователям)
def book_list(request):
    user = None
    if is_authenticated(request):
        user_id = request.session.get('user_id')
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            pass  # Если пользователя с таким ID не существует, оставляем user = None

    # Получаем параметры сортировки и порядка
    sort_by = request.GET.get('sort_by', 'title')  # Сортировка по умолчанию - по названию
    order = request.GET.get('order', 'asc')  # Порядок по умолчанию - по возрастанию

    # Определяем правильный порядок сортировки
    if order == 'desc':
        order_by = '-' + sort_by
    else:
        order_by = sort_by

    # Получаем список книг и сортируем
    books = Book.objects.all().order_by(order_by)

    paginator = Paginator(books, 10)  # N элементов на странице
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    return render(request, 'books/book_list.html', {'page_obj': page_obj, 'user': user, 'sort_by': sort_by, 'order': order})

# Страница создания книги (доступна только авторизованным пользователям)
def book_create(request):
    if not is_authenticated(request):
        return redirect('login_user')  # Перенаправляем на страницу входа, если не аутентифицирован
    # Защита от SQL-инъекций
    if request.method == "POST":
        form = BookForm(request.POST) # Запрос проходит валидацию
        if form.is_valid(): # Проверяет данные на соответствие правилам модели
            form.save() # Сохраняет данные через Django ORM, который автоматически экранирует потенциально опасные символы, предотвращая SQL-инъекции
            return redirect('/')

    else:
        form = BookForm()
    return render(request, 'books/book_form.html', {'form': form})

# Страница редактирования книги (доступна только авторизованным пользователям и администраторам)
def book_update(request, pk):
    if not is_authenticated(request):
        return redirect('login_user')  # Перенаправляем на страницу входа, если не аутентифицирован

    user_id = request.session.get('user_id')
    user = get_object_or_404(User, id=user_id)
    if not is_admin(user):
        return redirect('book_list')  # Если не администратор, перенаправляем на список книг

    book = get_object_or_404(Book, pk=pk)
    if request.method == "POST":
        form = BookForm(request.POST, instance=book)
        if form.is_valid():
            form.save()
            return redirect('/')
    else:
        form = BookForm(instance=book)
    return render(request, 'books/book_form.html', {'form': form})

# Страница удаления книги (доступна только администраторам)
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

# Страница выхода
def logout_user(request):
    logout(request)  # Завершаем сессию пользователя
    return redirect('/')  # Перенаправляем на страницу входа

# Проверка на аутентифицированного пользователя
def is_authenticated(request):
    user_id = request.session.get('user_id')
    return user_id is not None


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


# Функция кастомной аутентификации с проверкой хешированного пароля
def custom_authenticate(username, password):
    user = User.objects.filter(username=username).first()  # Получаем первого пользователя с данным логином
    if user and check_password(password, user.password):
        return user
    return None



# Страница регистрации (с хэшированием пароля)
def register(request):
    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']
        name = request.POST['name']
        is_admin = 'isAdmin' in request.POST

        # Проверка уникальности логина
        if User.objects.filter(username=username).exists():
            return render(request, 'books/register.html', {'error': 'Логин уже занят'})

        # Хэшируем пароль перед сохранением
        hashed_password = make_password(password)

        # Создаем пользователя с хэшированным паролем
        user = User(username=username, password=hashed_password, email=email, name=name, isAdmin=is_admin)
        user.save()

        # Выполняем вход в систему сразу после регистрации
        request.session['user_id'] = user.id  # Сохраняем ID пользователя в сессии
        login(request, user)  # Входим в систему

        return redirect('book_list')  # Редирект на страницу списка книг

    return render(request, 'books/register.html')

def check_username(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        user_exists = User.objects.filter(username=username).exists()
        return JsonResponse({'exists': user_exists})
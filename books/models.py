from django.db import models

class Book(models.Model):
    title = models.CharField(max_length=255)
    author = models.CharField(max_length=255)
    price = models.DecimalField(max_digits=10, decimal_places=2)

    def __str__(self):
        return self.title

class User(models.Model):
    id = models.AutoField(primary_key=True)
    username = models.TextField()
    password = models.TextField()
    email = models.TextField()
    name = models.TextField()
    isAdmin = models.BooleanField()
    last_login = models.DateTimeField(null=True, blank=True)  # Добавляем поле last_login

    def update_last_login(self):
        self.last_login = timezone.now()
        self.save()
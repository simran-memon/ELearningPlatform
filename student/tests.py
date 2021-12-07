from django.test import TestCase
from student.models import Student
from .models import User

class StudentTest(TestCase):
    def setUp(self):
        self.user = User(username='archana', first_name='archana', last_name='kamath')
        self.user.save()
        self.student = Student(user=self.user,address='test123@', mobile='test@example.com')
        self.student.save()

    def tearDown(self):
        self.user.delete()
        self.student.delete()
    
    def test_name(self):
        fullname = Student.get_name.__get__(self)
        #print(fullname)
        self.assertEqual(str(fullname), 'archana kamath')

    def test_instance(self):
        _self = Student.get_instance.__get__(self)
        #print(_self)
        self.assertEqual(_self, self)

    def test_str(self):
        __str__ = Student.__str__.__get__(self)
        #print(__str__)
        self.assertEqual(str(__str__), 'archana')

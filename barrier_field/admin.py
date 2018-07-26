# from django.contrib import admin
# from barrier_field.models import User
# from barrier_field.utils import get_user_data_model
# from barrier_field.reverse_admin import ReverseModelAdmin

# user_data_model = get_user_data_model()
# if user_data_model:
#     class UserAdmin(ReverseModelAdmin):
#         inline_type = 'tabular'
#         inline_reverse = ['user_data']
#     admin.site.register(User, UserAdmin)
# else:
#     admin.site.register(User)

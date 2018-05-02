from django import template

register = template.Library()


@register.filter(name='field_class')
def field_class(field, class_name):
    return field.as_widget(attrs={'class': class_name})
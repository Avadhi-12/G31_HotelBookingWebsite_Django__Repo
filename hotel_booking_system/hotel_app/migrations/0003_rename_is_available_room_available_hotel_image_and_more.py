# Generated by Django 5.2 on 2025-04-10 20:15

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('hotel_app', '0002_hotel_price_per_night_hotel_rating_and_more'),
    ]

    operations = [
        migrations.RenameField(
            model_name='room',
            old_name='is_available',
            new_name='available',
        ),
        migrations.AddField(
            model_name='hotel',
            name='image',
            field=models.ImageField(blank=True, null=True, upload_to='hotel_images/'),
        ),
        migrations.AddField(
            model_name='room',
            name='capacity',
            field=models.IntegerField(default=2),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name='room',
            name='hotel',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='rooms', to='hotel_app.hotel'),
        ),
        migrations.AlterField(
            model_name='room',
            name='price',
            field=models.DecimalField(decimal_places=2, max_digits=10),
        ),
    ]

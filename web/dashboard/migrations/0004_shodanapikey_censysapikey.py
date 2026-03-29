from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dashboard', '0003_alter_project_insert_date'),
    ]

    operations = [
        migrations.CreateModel(
            name='ShodanAPIKey',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('key', models.CharField(max_length=500)),
            ],
        ),
        migrations.CreateModel(
            name='CensysAPIKey',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('api_id', models.CharField(max_length=500)),
                ('secret', models.CharField(max_length=500)),
            ],
        ),
    ]

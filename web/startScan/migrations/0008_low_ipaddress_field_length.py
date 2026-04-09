# LOW-12: Increase IpAddress field lengths for IPv6 CIDR support

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('startScan', '0007_med_fixes_rename_fields_add_indexes'),
    ]

    operations = [
        migrations.AlterField(
            model_name='ipaddress',
            name='address',
            field=models.CharField(max_length=150, blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='ipaddress',
            name='reverse_pointer',
            field=models.CharField(max_length=150, blank=True, null=True),
        ),
    ]

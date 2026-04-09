# MED-05/06/07: Rename ambiguous fields and add database indexes

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('startScan', '0006_add_cfg_proxy_mode'),
    ]

    operations = [
        # MED-05: Rename scan_of → scan_history (db_column keeps old column name)
        migrations.RenameField(
            model_name='scanactivity',
            old_name='scan_of',
            new_name='scan_history',
        ),
        # MED-06: Rename time → created_at on ScanActivity (db_column keeps old column name)
        migrations.RenameField(
            model_name='scanactivity',
            old_name='time',
            new_name='created_at',
        ),
        # MED-06: Rename time → created_at on Command (db_column keeps old column name)
        migrations.RenameField(
            model_name='command',
            old_name='time',
            new_name='created_at',
        ),
        # MED-07: Add db_index to frequently queried fields
        migrations.AlterField(
            model_name='subdomain',
            name='name',
            field=models.CharField(max_length=1000, db_index=True),
        ),
        migrations.AlterField(
            model_name='vulnerability',
            name='severity',
            field=models.IntegerField(db_index=True),
        ),
        migrations.AlterField(
            model_name='vulnerability',
            name='http_url',
            field=models.CharField(max_length=10000, null=True, db_index=True),
        ),
        migrations.AlterField(
            model_name='endpoint',
            name='http_url',
            field=models.CharField(max_length=30000, db_index=True),
        ),
        migrations.AlterField(
            model_name='email',
            name='address',
            field=models.CharField(max_length=200, blank=True, null=True, db_index=True),
        ),
    ]

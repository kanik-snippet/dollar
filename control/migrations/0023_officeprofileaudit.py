from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("control", "0022_bootstrap_audit_indexes"),
    ]

    operations = [
        migrations.CreateModel(
            name="OfficeAuditRequest",
            fields=[],
            options={
                "verbose_name": "Office audit request",
                "verbose_name_plural": "Office audit requests",
                "proxy": True,
                "indexes": [],
                "constraints": [],
            },
            bases=("control.proxygenerationjob",),
        ),
        migrations.CreateModel(
            name="OfficeProfileAudit",
            fields=[],
            options={
                "verbose_name": "Office profile audit log",
                "verbose_name_plural": "Office profile audit logs",
                "proxy": True,
                "indexes": [],
                "constraints": [],
            },
            bases=("control.profileactivity",),
        ),
        migrations.CreateModel(
            name="OfficeAuditDomain",
            fields=[],
            options={
                "verbose_name": "Office audit domain log",
                "verbose_name_plural": "Office audit domain logs",
                "proxy": True,
                "indexes": [],
                "constraints": [],
            },
            bases=("control.profiledomainactivity",),
        ),
    ]

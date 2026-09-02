from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [("control", "0007_proxy_pool_inventory")]

    operations = [
        migrations.CreateModel(
            name="ProfileDomainActivity",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("session_id", models.CharField(db_index=True, max_length=64)),
                ("group_id", models.CharField(blank=True, db_index=True, max_length=64)),
                ("profile_name", models.CharField(blank=True, max_length=160)),
                ("profile_id", models.CharField(db_index=True, max_length=128)),
                ("browser_id", models.CharField(blank=True, max_length=64)),
                ("domain", models.CharField(db_index=True, max_length=253)),
                ("first_visited_at", models.DateTimeField()),
                ("last_visited_at", models.DateTimeField()),
                ("visit_count", models.PositiveIntegerField(default=1)),
                ("session_started_at", models.DateTimeField()),
                ("session_ended_at", models.DateTimeField()),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("client", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="profile_domain_activity", to="control.clientaccess")),
                ("job", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="profile_domain_activity", to="control.proxygenerationjob")),
                ("reservation", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="profile_domain_activity", to="control.proxyreservation")),
            ],
            options={"verbose_name_plural": "Profile domain activity", "ordering": ("-last_visited_at", "domain")},
        ),
        migrations.AddConstraint(
            model_name="profiledomainactivity",
            constraint=models.UniqueConstraint(fields=("client", "profile_id", "session_id", "domain"), name="unique_profile_session_domain"),
        ),
    ]

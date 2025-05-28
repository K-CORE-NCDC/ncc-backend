from django.db import models
from django.contrib.auth import get_user_model
from django.db.models import JSONField

User = get_user_model()

class UserDataProjects(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=255,null=True, default=None)
    dna_mutation = models.CharField(max_length=255, null=True, default=None)
    methylation = models.CharField(max_length=255, null=True, default=None)
    rna = models.CharField(max_length=255, null=True, default=None)
    proteome = models.CharField(max_length=255, null=True, default=None)
    clinical_information = models.CharField(max_length=255, null=True, default=None)
    cnv = models.CharField(max_length=255, null=True, default=None)
    phospho = models.CharField(max_length=255, null=True, default=None)
    fusion = models.CharField(max_length=255, null=True, default=None)
    sql_path = models.CharField(max_length=155, blank=True)
    is_clinical = models.BooleanField(blank=True, null=True)
    available_steps = JSONField(default=dict)
    viz_type = models.CharField(max_length=255, default=None)
    uploaded_date = models.DateTimeField(auto_now=True, null=True)
    #make it unique UUID in future
    project_id = models.CharField(max_length=55,unique=True)
    # project_status = models.CharField(max_length=255, unique=False, null=True)
    # error_found = models.CharField(max_length=255, unique=False, null=True)
    # # error_found= JSONField(default=dict)
    # response = models.JSONField(default=dict)


class MasterPhospho(models.Model):
    hugo_symbol = models.CharField(max_length=255, blank=False, null=False)
    swiss_prot_acc_id = models.CharField(max_length=255, blank=False, null=False)

    class Meta:
        managed = True
        db_table = "masterphospho"

class UserDataExtension(models.Model):
    username = models.CharField(max_length=255)
    project_name = models.CharField(max_length=255, unique=True)
    project_id = models.CharField(max_length=255, unique=True, default=None)
    files = JSONField(default=dict)
    uploaded_date = models.DateTimeField(auto_now=True, null=True)
    extended_on = models.DateTimeField(null=True)
    reason_for_extension = models.TextField(null=True, default=None)
    deleted_on = models.DateTimeField(null=True)

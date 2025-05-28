from django.db import models
from django.db.models.fields import TextField
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.utils.translation import ugettext_lazy as _


class UserManager(BaseUserManager):
    """Define a model manager for User model with no username field."""

    use_in_migrations = True

    def _create_user(self, email, password, **extra_fields):
        """Create and save a User with the given email and password."""
        if not email:
            raise ValueError("The given email must be set")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra_fields):
        """Create and save a regular User with the given email and password."""
        extra_fields.setdefault("is_staff", False)
        extra_fields.setdefault("is_superuser", False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password, **extra_fields):
        """Create and save a SuperUser with the given email and password."""
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self._create_user(email, password, **extra_fields)


class User(AbstractUser):
    """User model."""

    user_id = models.CharField(max_length=200, default="",db_column='user_id_app')  # Renamed field
    requested_date = models.DateTimeField(auto_now_add=True, null=True)
    approved_date = models.DateTimeField(null=True)  # New field for approval date
    objects = UserManager()



class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    forget_password_token = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)
    unique_pin = models.IntegerField(blank=True, null=True)

    def __str__(self):
        return self.user.user_id


class RnidDetails(models.Model):
    ybc_key = models.CharField(unique=True, max_length=55)
    rn_key = models.CharField(unique=True, max_length=55)
    brst_key = models.CharField(unique=True, max_length=55)
    dna_mutation = models.BooleanField(blank=True, null=True, db_column='dna_mutation_rnid') # Renamed field
    methylationtab = models.BooleanField(blank=True, null=True)
    rnas = models.BooleanField(blank=True, null=True)
    phosphotab = models.BooleanField(blank=True, null=True)
    proteomes = models.BooleanField(blank=True, null=True)
    cnv = models.BooleanField(blank=True, null=True, db_column='cnv_rnid')  # Renamed field
    fusion_gene = models.BooleanField(blank=True, null=True)
    total = models.IntegerField(blank=True, null=True)
    image = models.IntegerField(blank=True, null=True)

    class Meta:
        db_table = "rnid"



class ClinicalInformation(models.Model):
    pt_sbst_no = models.CharField(max_length=155, blank=True, null=True)
    bmi_vl = models.FloatField(blank=True, null=True)
    stage = models.CharField(max_length=155, blank=True, null=True)
    # rgst_ymd = models.DateField(blank=True, null=True)
    drnk_yn = models.BooleanField(blank=True, null=True)
    hyp_yn = models.BooleanField(blank=True, null=True)
    diabetes_yn = models.BooleanField(blank=True, null=True)
    smok_curr_yn = models.BooleanField(blank=True, null=True)
    smok_yn = models.BooleanField(blank=True, null=True)
    # smoker= models.CharField(max_length=155, blank=True, null=True) #new
    # fmhs_brst_yn = models.BooleanField(blank=True, null=True)
    # oc_yn = models.BooleanField(blank=True, null=True)
    # hrt_yn = models.BooleanField(blank=True, null=True)
    # mena_age = models.FloatField(blank=True, null=True)
    # meno_yn = models.BooleanField(blank=True, null=True)
    # delv_yn = models.BooleanField(blank=True, null=True)
    # feed_yn = models.BooleanField(blank=True, null=True)
    # feed_drtn_mnth = models.FloatField(blank=True, null=True)
    # bila_cncr_yn = models.BooleanField(blank=True, null=True)
    # rgst_dt = models.CharField(max_length=155, blank=True, null=True)
    # imnl_read_ymd = models.DateField(blank=True, null=True)
    # er_score = models.IntegerField(blank=True, null=True)
    # pr_score = models.IntegerField(blank=True, null=True)
    # her2_score = models.CharField(max_length=155, blank=True, null=True)
    # ki67_score = models.IntegerField(blank=True, null=True)
    t_category = models.CharField(max_length=155, blank=True, null=True)
    n_category = models.CharField(max_length=155, blank=True, null=True)
    sex_cd = models.CharField(max_length=155, blank=True, null=True)
    diag_age = models.IntegerField(blank=True, null=True)
    rlps_yn = models.BooleanField(blank=True, null=True)
    # rlps_date = models.DateField(blank=True, null=True)
    rlps_cnfr_drtn = models.FloatField(blank=True, null=True)
    death_yn = models.BooleanField(blank=True, null=True)
    death_cnfr_drtn = models.FloatField(blank=True, null=True)
    rnid = models.ForeignKey(
        RnidDetails, models.DO_NOTHING, db_column="rnid", blank=True, null=True
    )

    class Meta:
        db_table = "clinical_information"


class Cnv(models.Model):
    chromosome = models.CharField(max_length=50, blank=True, null=True) #length changed
    start_pos = models.IntegerField(blank=True, null=True)
    end_pos = models.IntegerField(blank=True, null=True)
    gene = models.CharField(max_length=55, blank=True, null=True)
    log2 = models.FloatField(blank=True, null=True)
    cn = models.IntegerField(blank=True, null=True)
    depth = models.FloatField(blank=True, null=True)
    probes = models.IntegerField(blank=True, null=True)
    weight = models.FloatField(blank=True, null=True)
    r_fk = models.ForeignKey(
        RnidDetails, on_delete=models.CASCADE, related_name="cnv_fk"
    )

    class Meta:
        db_table = "cnv"


class DnaMutation(models.Model):
    hugo_symbol = models.CharField(max_length=255, blank=True, null=True)
    chromosome = models.CharField(max_length=50, blank=True, null=True)
    start_position = models.IntegerField(blank=True, null=True)
    end_position = models.IntegerField(blank=True, null=True)
    strand = models.CharField(max_length=255, blank=True, null=True)
    variant_classification = models.CharField(max_length=255, blank=True, null=True) #length changed, issue
    variant_type = models.CharField(max_length=255, blank=True, null=True)
    tumor_sample_barcode = models.CharField(max_length=155, blank=True, null=True)
    annotation_transcript = models.CharField(max_length=155, blank=True, null=True)
    protein_change = models.CharField(max_length=255, blank=True, null=True)
    refseq_mrna_id = models.CharField(max_length=255, blank=True, null=True)
    swiss_prot_acc_id = models.CharField(max_length=255, blank=True, null=True)
    gc_content = models.CharField(max_length=255, blank=True, null=True)
    rnid = models.ForeignKey(RnidDetails, models.DO_NOTHING, db_column="rnid", blank=True, null=True)

    class Meta:
        db_table = "dna_mutation"



class Hg38(models.Model):
    hugo_symbol = models.CharField(max_length=255, blank=True, null=True)
    gene_description = models.CharField(max_length=255, blank=True, null=True)
    start_position = models.IntegerField(blank=True, null=True)
    end_position = models.IntegerField(blank=True, null=True)
    chromosome = models.CharField(max_length=50, blank=True, null=True)
    gene_stable_id = models.CharField(max_length=155, blank=True, null=True)
    gene_stable_id_version = models.CharField(
        max_length=155, blank=True, null=True)

    class Meta:
        db_table = "hg38"


class Interpro(models.Model):
    protein = models.CharField(max_length=155, blank=True, null=True)
    ipr = models.CharField(max_length=155, blank=True, null=True)
    domain = models.TextField(blank=True, null=True)
    pfamid = models.CharField(max_length=155, blank=True, null=True)
    start_codon = models.IntegerField(blank=True, null=True)
    end_codon = models.IntegerField(blank=True, null=True)

    class Meta:
        db_table = "interpro"


class Methylation(models.Model):
    pt_sbst_no = models.CharField(max_length=155, blank=True, null=True)
    gene_name = models.CharField(max_length=155, blank=True, null=True)
    target_id = models.CharField(max_length=155, blank=True, null=True)
    target_type = models.CharField(max_length=25, blank=True, null=True)
    gene_vl = models.FloatField(blank=True, null=True)
    rnid = models.ForeignKey(
        RnidDetails, models.DO_NOTHING, db_column="rnid", blank=True, null=True
    )

    class Meta:
        db_table = "methylation"


class OncoSampleImagesInfo(models.Model):
    file_name = models.CharField(max_length=255, blank=True, null=True)
    rnid = models.ForeignKey(
        RnidDetails, models.DO_NOTHING, db_column="rnid", blank=True, null=True
    )

    class Meta:
        db_table = "onco_sample_images_info"


class Phospho(models.Model):
    pt_sbst_no = models.CharField(max_length=155, blank=True, null=True)
    type = models.CharField(max_length=25, blank=True, null=True)
    batch_id = models.CharField(max_length=155, blank=True, null=True)
    gene_name = models.CharField(max_length=155, blank=True, null=True)
    site = models.CharField(max_length=45, blank=True, null=True)
    description = models.CharField(max_length=255, blank=True, null=True)
    gene_vl = models.FloatField(blank=True, null=True)
    z_score = models.FloatField(blank=True, null=True)
    # rnid_fk = models.ForeignKey(RnidDetails, models.DO_NOTHING, db_column='rnid', blank=True, null=True)
    rnid = models.ForeignKey(
        RnidDetails, models.DO_NOTHING, db_column="rnid", blank=True, null=True
    )

    class Meta:
        db_table = "phospho"


class Proteome(models.Model):
    pt_sbst_no = models.CharField(max_length=155, blank=True, null=True)
    type = models.CharField(max_length=25, blank=True, null=True)
    batch_id = models.CharField(max_length=155, blank=True, null=True)
    gene_name = models.CharField(max_length=155, blank=True, null=True)
    p_name = models.CharField(max_length=155, blank=True, null=True)
    gene_vl = models.FloatField(blank=True, null=True)
    z_score = models.FloatField(blank=True, null=True)
    rnid = models.ForeignKey(
        RnidDetails, models.DO_NOTHING, db_column="rnid", blank=True, null=True
    )

    class Meta:
        db_table = "proteome"


class Rna(models.Model):
    pt_sbst_no = models.CharField(max_length=155, blank=True, null=True)
    gene_name = models.CharField(max_length=155, blank=True, null=True)
    gene_vl = models.FloatField(blank=True, null=True)
    z_score = models.FloatField(blank=True, null=True)
    type = models.CharField(max_length=25, blank=True, null=True) #length changed
    rnid = models.ForeignKey(
        RnidDetails, models.DO_NOTHING, db_column="rnid", blank=True, null=True
    )

    class Meta:
        db_table = "rna"


class GenevariantsankeyNew(models.Model):
    hugo_symbol = models.CharField(max_length=255, blank=True, null=True)
    variant_classification = models.CharField(
        max_length=255, blank=True, null=True)
    dbsnp_rs = models.CharField(max_length=255, blank=True, null=True)
    diseasename = models.CharField(max_length=255, blank=True, null=True)
    drugname = models.CharField(max_length=255, blank=True, null=True)
    sourceurl = models.TextField(blank=True, null=True)
    pmid_count = models.IntegerField(blank=True, null=True)

    class Meta:

        db_table = "genevariantsankeynew"


class Fusion(models.Model):
    left_gene_name = models.CharField(max_length=100, blank=True, null=True)
    left_gene_ensmbl_id = models.CharField(
        max_length=100, blank=True, null=True)
    left_gene_chr = models.CharField(max_length=100, blank=True, null=True)
    left_gene_pos = models.IntegerField(blank=True, null=True)
    left_hg38_pos = models.IntegerField(blank=True, null=True)
    right_gene_name = models.CharField(max_length=100, blank=True, null=True)
    right_gene_ensmbl_id = models.CharField(
        max_length=100, blank=True, null=True)
    right_gene_chr = models.CharField(max_length=100, blank=True, null=True)
    right_gene_pos = models.IntegerField(blank=True, null=True)
    right_hg38_pos = models.IntegerField(blank=True, null=True)
    junction_read_count = models.IntegerField(blank=True, null=True)
    spanning_frag_count = models.IntegerField(blank=True, null=True)
    splice_type = models.CharField(max_length=100, blank=True, null=True)
    rnid = models.ForeignKey(
        RnidDetails, models.DO_NOTHING, db_column="rnid", blank=True, null=True
    )

    class Meta:
        db_table = "fusion"


class DownloadVisualization(models.Model):
    id = models.AutoField(primary_key=True, db_column='id_down') # renamed field
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    created_on = models.DateTimeField(auto_now_add=True, blank=True)
    chart_name = models.CharField(max_length=255, blank=True, null=True)
    # project_id = models.IntegerField(blank=True, null=True, db_column='project_id_app') # renamed field
    project_id = models.CharField(max_length=255, blank=True, null=True,db_column='project_id_app')
    ip_address = models.CharField(max_length=255, blank=True, null=True)
    category = models.CharField(max_length=255, blank=True, null=True)
    indexes = [
        models.Index(fields=['chart_name']),
    ]


class SessionDetails(models.Model):
    session_id = models.CharField(max_length=255, blank=True, null=True)
    url = models.TextField(blank=True, null=True)
    start_time = models.CharField(max_length=255, blank=True, null=True)
    end_time = models.CharField(max_length=255, blank=True, null=True)
    visitedDate = models.DateField(max_length=255, blank=True, null=True)
    ip_address = models.CharField(max_length=255, blank=True, null=True)
    latitude = models.FloatField(blank=True, null=True)
    langitude = models.FloatField(blank=True, null=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    category = models.CharField(max_length=255, blank=True, null=True)
    viz_type = models.CharField(max_length=255, blank=True, null=True)
    tab_name = models.CharField(max_length=255, blank=True, null=True)

    class Meta:
        managed = True
        db_table = "sessiondetails"
        indexes = [
            models.Index(fields=['tab_name']),
        ]


class OutputGTF(models.Model):
    id = models.AutoField(primary_key=True)
    region = models.CharField(max_length=255, blank=True, null=True)
    gtf_start = models.IntegerField(blank=True, null=True)
    gtf_end = models.IntegerField(blank=True, null=True)
    gene_id = models.CharField(max_length=255, blank=True, null=True)
    transcript_id = models.CharField(max_length=255, blank=True, null=True)
    gene_name = models.CharField(max_length=155, blank=True, null=True) #length changed
    gtf_exon = models.CharField(max_length=255, blank=True, null=True)
    rel_start = models.IntegerField(blank=True, null=True)
    rel_end = models.IntegerField(blank=True, null=True)
    gtf_length = models.IntegerField(blank=True, null=True)

    class Meta:
        db_table = 'output_gtf'

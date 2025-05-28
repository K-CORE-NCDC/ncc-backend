import os
import math
import random
import logging
import sqlite3 as sql
from io import BytesIO
from datetime import datetime
import pandas as pd
from django.conf import settings
from lifelines import CoxPHFitter
from django.http import HttpResponse
from rest_framework.response import Response
from django.template.loader import get_template
from user_data_visualization.models import UserDataProjects

volcano_static = {
    "t_category": ["Tis,T1,T2", "T3,T4"],
    "n_category": ["Nx,N0,N1,N2", "N3"],
    # "her2_score": ["0,0~1,1+", "2,2+,3+"],
}

dynamic_her2 = {
    "negative (0-1+)": ["0", "0~1", "1+"],
    "equivocal (2+)": ["2", "2+"],
    "positive (3+)": ["3", "3+"],
}
fusion_her2 = {
    "negative (0-2+)": ["0", "0~1", "1+", "2", "2+"],
    "positive (3+)": ["3", "3+"],
}
dynamic_ki67 = {"low": [0, 15], "intermediate": [15, 30], "high": [30, 100]}

advance_filter_fields_types = {
    "diag_age": "number",
}
advance_filter_fields = {
    "sex_male": {"key": "sex_cd", "value": "'M'", "custom": True},
    "sex_female": {"key": "sex_cd", "value": "'F'", "custom": True},
    "from_aod": {"key": "diag_age", "value": True, "range": "from"},
    "to_aod": {"key": "diag_age", "value": True, "range": "to"},
    "from_bmi": {"key": "bmi_vl", "value": True, "range": "from"},
    "to_bmi": {"key": "bmi_vl", "value": True, "range": "to"},
    # "from_ki67": {"key": "ki67_score", "range": "from", "value": True},
    # "to_ki67": {"key": "ki67_score", "range": "from", "value": True},
    "from_turc": {"key": "rlps_cnfr_drtn", "value": True, "range": "from"},
    "to_turc": {"key": "rlps_cnfr_drtn", "value": True, "range": "to"},
    # "from_fma": {"key": "mena_age", "value": True, "range": "from"},
    # "to_fma": {"key": "mena_age", "value": True, "range": "to"},
    # "from_dob": {"key": "feed_drtn_mnth", "value": True, "range": "from"},
    # "to_dob": {"key": "feed_drtn_mnth", "value": True, "range": "to"},
    # "dbbc_to": {"key": "bila_cncr_yn", "value": False, "bool": True},
    # "menopause_yes": {"key": "meno_yn", "value": True, "bool": True},
    # "dbbc_from": {"key": "bila_cncr_yn", "value": True, "bool": True},
    "current_smoker": {"key": "smok_curr_yn", "value": True, "bool": True},
    "former_smoker": {"key": "smok_yn", "value": True, "bool": True},
    "non_smoker": {"key": "smok_yn", "value": False, "bool": True},
    "stage_I": {"key": "stage", "value": "stage_I", "custom": True},
    "stage_II": {"key": "stage", "value": "stage_II", "custom": True},
    "stage_III": {"key": "stage", "value": "stage_III", "custom": True},
    "stage_IV": {"key": "stage", "value": "stage_IV", "custom": True},
    # "fhbc_yes": {"key": "fmhs_brst_yn", "value": True, "bool": True},
    # "fhbc_no": {"key": "fmhs_brst_yn", "value": False, "bool": True},
    # "menopause_no": {"key": "meno_yn", "value": False, "bool": True},
    # "childbirth_yes": {"key": "delv_yn", "value": True, "bool": True},
    # "childbirth_no": {"key": "delv_yn", "value": False, "bool": True},
    # "eob_yes": {"key": "feed_yn", "value": True, "bool": True},
    # "eob_no": {"key": "feed_yn", "value": False, "bool": True},
    # "hrt_yes": {"key": "hrt_yn", "value": True, "bool": True},
    # "hrt_no": {"key": "hrt_yn", "value": False, "bool": True},
    # "cr_yes": {"key": "rlps_yn", "value": True, "bool": True},
    # "cr_no": {"key": "rlps_yn", "value": False, "bool": True},
    # "iocp_yes": {"key": "oc_yn", "value": True, "bool": True},
    # "iocp_no": {"key": "oc_yn", "value": False, "bool": True},
    # "tstage_is": {"key": "t_category", "value": "Tis", "t_category": True},
    "tstage_1": {"key": "t_category", "value": "T1", "t_category": True},
    "tstage_2": {"key": "t_category", "value": "T2", "t_category": True},
    "tstage_3": {"key": "t_category", "value": "T3", "t_category": True},
    "tstage_4": {"key": "t_category", "value": "T4", "t_category": True},
    # "nstage_nx": {"key": "n_category", "value": "Nx", "n_category": True},
    "nstage_n0": {"key": "n_category", "value": "N0", "n_category": True},
    "nstage_n1": {"key": "n_category", "value": "N1", "n_category": True},
    "nstage_n2": {"key": "n_category", "value": "N2", "n_category": True},
    "nstage_n3": {"key": "n_category", "value": "N3", "n_category": True},
    # "nstage_ii": {"key": "n_category", "value": "2a"},
    # "nstage_iii": {"key": "n_category", "value": "2a"},
    "hyp_yes": {"key": "hyp_yn", "value": True, "bool": True},
    "hyp_no": {"key": "hyp_yn", "value": False, "bool": True},
    "diabetes_no": {"key": "diabetes_yn", "value": False, "bool": True},
    "diabetes_yes": {"key": "diabetes_yn", "value": True, "bool": True},
    # "etr_yes": {"key": "er_score", "value": 1},
    # "etr_no": {"key": "er_score", "value": 2},
    # "etr_na": {"key": "er_score", "value": 0},
    # "ptr_yes": {"key": "pr_score", "value": 1},
    # "ptr_no": {"key": "pr_score", "value": 2},
    # "ptr_na": {"key": "pr_score", "value": 0},
    # "herscore_o": {"key": "her2_score", "value": "0"},
    # "herscore_o1": {"key": "her2_score", "value": "0~1+"},
    # "herscore_1": {"key": "her2_score", "value": "1+"},
    # "herscore_2": {"key": "her2_score", "value": "2"},
    # "herscore_2+": {"key": "her2_score", "value": "2+"},
    # "herscore_3+": {"key": "her2_score", "value": "3+"},
    "ac_yes": {"key": "drnk_yn", "value": "Y"},
    "ac_no": {"key": "drnk_yn", "value": "N"},

}


logger = logging.getLogger(__name__)

def add_line_in_logger_file():
    today_date = datetime.now().strftime('%d-%m-%Y')
    LOG_FILE = os.path.join(settings.BASE_DIR, f"media/log_files/{today_date}_Exceptions.log")
    try:
        # Ensure the log file directory exists
        # log_dir = os.path.dirname(LOG_FILE)
        # if not os.path.exists(log_dir):
        #     os.makedirs(log_dir)
        # Add a separator line to the log file
        with open(LOG_FILE, 'a') as log_file:
            log_file.write('\n' * 2)  # Add two blank lines for separation
            log_file.write('-' * 50 + '\n')  # You can customize the separator line here

    except Exception as e:
        # Handle any exceptions when creating the log file or directory
        logging.exception(f"Something Went wrong in Logger: {str(e)}")

def format_number_roundup(number):
    if number == 0:
        return 0

    abs_number = abs(number)

    # Check if all digits are zero
    if abs_number < 1e-4:
        return f"{number:.4e}"

    # Round to 4 decimal places
    formatted_number = round(number, 4)

    return formatted_number


def color():
    return random.randint(0, 255)


def stack_data_generator(data, type):
    labels = {}
    symbols = []
    vc_l = []
    for e in data:
        if e.label not in symbols:
            symbols.append(e.label)
        if e.vc not in vc_l:
            vc_l.append(e.vc)

        name = e.label + "||" + e.vc
        if name in labels:
            labels[name] = labels[name] + e.count
        else:
            labels[name] = e.count

    datasets = []
    r_c_ = {
        "In_Frame_Del": "#1b4879",
        "In_Frame_Ins": "#c74951",
        "Frame_Shift_Del": "#603d92",
        "Frame_Shift_Ins": "#3778ae",
        "Nonsense_Mutation": "#d3352b",
        "Splice_Site": "#f28432",
        "Germline": "#000000",
        "Missense_Mutation": "#549d3e",
        "T": "#549d3e",
        "N": "#d3352b",
    }

    for e in vc_l:
        t = []
        r_c = f"#{color():02X}{color():02X}{color():02X}"
        for s in symbols:
            z = 0
            n = s + "||" + e
            if n in labels:
                z = labels[n]
            t.append(z)

        if e in r_c_:
            temp = {"label": e, "data": t, "backgroundColor": r_c_[e]}
        else:
            temp = {"label": e, "data": t, "backgroundColor": r_c}

        if type == "dna_per_sample":
            temp["barPercentage"] = 1.0
            temp["categoryPercentage"] = 1.0

        datasets.append(temp)

    return {"datasets": datasets, "labels": symbols}


def int_converter_(a):
    a = a.strip()
    if len(a) > 0:
        try:
            return int(a)
        except:
            return None
    else:
        return None


def float_converter(a):
    if a == "0":
        return True

    if a.isdigit():
        return True

    if "e" in a or "E" in a:
        parts = a.split("e") if "e" in a else a.split("E")
        if (
            len(parts) == 2
            and parts[0].replace(".", "").replace("-", "").isdigit()
            and parts[1].replace("-", "").isdigit()
        ):
            return True

    if a.count(".") == 1 or a.count("-") == 1:
        if "-" in a:
            if a.replace(".", "").replace("-", "").isdigit():
                return True
        else:
            if a.replace(".", "").isdigit():
                return True

    return False


def int_converter(a):
    try:
        return math.ceil(float(a))
    except Exception:
        if len(a) == 0:
            return 0
        return math.ceil(float(a))


def date_converter(a):
    a = a.strip()
    if len(a) > 0:
        try:
            x = datetime.strptime(a, "%d-%m-%Y")
            return x.date()
        except Exception:
            return None
    else:
        return None


def bool_converter(a):
    a_len = len(a)
    if not a_len > 0:
        return None
    a_lower = a.lower()
    if a_lower in ("true", "t", "y", "yes"):
        return True
    if a_lower in ("false", "f", "n", "no"):
        return True
    return False if len(a) == 0 else Exception("error bool", a)


def str_converter(a):
    a = a.strip()
    if len(a) > 0:
        return a
    return None


def yes_no_converter(a):
    a_len = len(a)
    if not a_len > 0:
        return None
    a_lower = a.lower()
    if a_lower in ("true", "t", "y", "yes"):
        return "Y"
    if a_lower in ("false", "f", "n", "no"):
        return "N"
    return None


def get_project_table(project_id):

    project_information = UserDataProjects.objects.get(id=project_id)
    database_path = project_information.sql_path
    try:
        project_database = {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": database_path,
            "ATOMIC_REQUESTS": False,
            "AUTOCOMMIT": True,
            "CONN_MAX_AGE": 0,
            "OPTIONS": {},
            "TIME_ZONE": None,
            "USER": "",
            "PASSWORD": "",
            "HOST": "",
            "PORT": "",
            "TEST": {
                "CHARSET": None,
                "COLLATION": None,
                "MIGRATE": True,
                "MIRROR": None,
                "NAME": None,
            },
        }
        settings.DATABASES["userdata"] = project_database
        conn = sql.connect(database_path)
        table_name = "clinical_information"
        query = f"PRAGMA table_info('{table_name}')"

        cursor = conn.execute(query)
        res = cursor.fetchall()

        result_json = {"Clinical Information": {}}

        for x in res:
            if x[1] != "pt_sbst_no" and x[1] != "id" and x[1] != "rnid":
                if x[2] == "VARCHAR(155)":
                    jobs = {
                        job[0]
                        for job in cursor.execute(
                            f"SELECT {x[1]} FROM clinical_information"
                        )
                    }
                    result_json["Clinical Information"][x[1]] = []
                    for text in jobs:
                        result_json["Clinical Information"][x[1]].append(
                            {
                                "type": "checkbox",
                                "name": x[1],
                                "id": f"{x[1]}_{text}",
                                "value": f"{text}",
                            }
                        )

                elif x[2] == "FLOAT" or x[2] == "INT":
                    result_json["Clinical Information"][x[1]] = []
                    query1 = (
                        f"SELECT MIN({x[1]}) , MAX({x[1]}) FROM clinical_information"
                    )
                    cursor1 = conn.execute(query1)
                    res1 = cursor1.fetchall()
                    min = 0
                    max = 0
                    if res1[0][0] is not None:
                        min = res1[0][0]
                    if res1[0][1] is not None:
                        max = res1[0][1]
                    result_json["Clinical Information"][x[1]].append(
                        {
                            "type": "number",
                            "name": x[1],
                            "id": x[1],
                            "min": min,
                            "max": max,
                        }
                    )
                elif x[2] == "BOOLEAN":
                    result_json["Clinical Information"][x[1]] = []
                    result_json["Clinical Information"][x[1]].append(
                        {
                            "type": "checkbox",
                            "name": x[1],
                            "id": f"{x[1]}_yes",
                            "value": "yes",
                        }
                    )
                    result_json["Clinical Information"][x[1]].append(
                        {
                            "type": "checkbox",
                            "name": x[1],
                            "id": f"{x[1]}_no",
                            "value": "no",
                        }
                    )

    except Exception as e2:
        print("e2", e2)

    return result_json


dna_mutation = {
    "hugo_symbol": str_converter,
    "entrez_gene_id": int_converter,
    "center": str_converter,
    "ncbi_build": str_converter,
    "chromosome": str_converter,
    "start_position": int_converter,
    "end_position": int_converter,
    "strand": str_converter,
    "variant_classification": str_converter,
    "variant_type": str_converter,
    "reference_allele": str_converter,
    "tumor_seq_allele1": str_converter,
    "tumor_seq_allele2": str_converter,
    "dbsnp_rs_dna": str_converter,
    "dbsnp_val_status": str_converter,
    "tumor_sample_barcode": str_converter,
    "genome_change": str_converter,
    "annotation_transcript": str_converter,
    "transcript_strand": str_converter,
    "transcript_exon": float_converter,
    "transcript_position": str_converter,
    "cdna_change": str_converter,
    "codon_change": str_converter,
    "protein_change": str_converter,
    "refseq_mrna_id": str_converter,
    "refseq_prot_id": str_converter,
    "swiss_prot_acc_id": str_converter,
    "ref_context": str_converter,
    "gc_content": float_converter,
    "ensembl_so_term": str_converter,
    "hgnc_chromosome": str_converter,
    "refseq_mrna_id_2": str_converter,
    "secondary_variant_classification": str_converter,
    "aa_size": str_converter,
}

methylation = {
    "pt_sbst_no": str_converter,
    "gene_name": str_converter,
    "target_id": str_converter,
    "target_type": str_converter,
    "gene_vl": float_converter,
}

rna = {
    "pt_sbst_no": str_converter,
    "gene_name": str_converter,
    "gene_vl": float_converter,
    "z_score": float_converter,
}

rna = {
    "pt_sbst_no": str_converter,
    "gene_name": str_converter,
    "gene_vl": float_converter,
    "z_score": float_converter,
    "type": str_converter,
}

proteome = {
    "pt_sbst_no": str_converter,
    "type": str_converter,
    "batch_id": str_converter,
    "gene_name": str_converter,
    "p_name": str_converter,
    "gene_vl": float_converter,
    "z_score": float_converter,
}

clinical_information = {
    "pt_sbst_no": str_converter,
    "bmi_vl": float_converter,
    # "rgst_ymd": date_converter,
    "drnk_yn": bool,
    "smok_curr_yn": bool,
    "smok_yn": bool,
    "diabetes_yn": bool,
    "hyp_yn": bool,
    "stage": str_converter,
    # # "mena_age": int_converter,
    # # "meno_yn": bool,
    # # "delv_yn": bool,
    # # "feed_yn": bool,
    # # "feed_drtn_mnth": int_converter,
    # # "bila_cncr_yn": bool,
    # # "rgst_dt": date_converter,
    # # "imnl_read_ymd": date_converter,
    # # "er_score": int_converter,
    # # "pr_score": int_converter,
    # # "her2_score": str_converter,
    # "ki67_score": int_converter,
    "t_category": str_converter,
    "n_category": str_converter,
    "sex_cd": str_converter,
    "diag_age": int_converter,
    "rlps_yn": bool,
    # "rlps_date": date_converter,
    "rlps_cnfr_drtn": float_converter,
    "death_yn": bool,
    "death_cnfr_drtn": float_converter,
}


deg_results = {
    "session": str_converter,
    "gene_name": str_converter,
    "fc": float_converter,
    "pvalue": float_converter,
}


fusion = {
    "left_gene_name": str_converter,
    "left_gene_ensmbl_id": str_converter,
    "left_gene_chr": str_converter,
    "left_gene_pos": int_converter,
    "right_gene_name": str_converter,
    "right_gene_ensmbl_id": str_converter,
    "right_gene_chr": str_converter,
    "right_gene_pos": int_converter,
    "pt_sbst_no": str_converter,
    "left_hg38_pos": int_converter,
    "right_hg38_pos": int_converter,
    "junction_read_count": int_converter,
    "spanning_frag_count": int_converter,
    "splice_type": str_converter,
}

phospho = {
    "pt_sbst_no": str_converter,
    "type": str_converter,
    "batch_id": str_converter,
    "gene_name": str_converter,
    "site": str_converter,
    "description": str_converter,
    "gene_vl": float_converter,
    "z_score": float_converter,
}


cnv = {
    "pt_sbst_no": str_converter,
    "chromosome": str_converter,
    "start_pos": int_converter,
    "end_pos": int_converter,
    "gene": str_converter,
    "log2": float_converter,
    "cn": int_converter,
    "depth": float_converter,
    "probes": int_converter,
    "weight": float_converter,
}

rnid_converter = {
    "id": int_converter,
    "ybc_key": str,
    "rn_key": str,
    "brst_key": str,
    "dna_mutation": bool_converter,
    "methylation": bool_converter,
    "rnas": bool_converter,
    "phospho": bool_converter,
    "proteomes": bool_converter,
    "cnv": bool_converter,
    "fusion_gene": bool_converter,
    "total": int_converter,
    "image": int_converter,
}

visualization_tables_requirement = {
    "circos": ["dna_mutation", "rna", "methylation", "proteome", "fusion", "cnv"],
    "heatmap": ["rna", "proteome", "methylation", "phospho"],
    "box": ["proteome", "rna"],
    "oncoprint": ["dna_mutation"],
    "lollypop": ["dna_mutation", "phospho"],
    "sankey": [ "dna_mutation", "proteome", "rna"],
    "survival": ["clinical_information"],
    "volcano": ["clinical_information", "rna"],
    "igv": ["cnv"],
    "scatter": ["rna", "proteome"],
    "fusion": ["clinical_information", "fusion"],
}


create_dna_mutation = """CREATE TABLE IF NOT EXISTS dna_mutation (
    hugo_symbol VARCHAR ( 255 ),
    tumor_sample_barcode VARCHAR ( 155 ),
    variant_classification VARCHAR ( 155 ),
    variant_type VARCHAR ( 255 ),
    chromosome VARCHAR ( 50 ),
    start_position INT,
    end_position INT,
    strand VARCHAR ( 255 ),
    protein_change VARCHAR ( 255 ),
    swiss_prot_acc_id VARCHAR ( 255 ),
    annotation_transcript VARCHAR ( 255 ),
    gc_content VARCHAR ( 255 ),
    refseq_mrna_id  varchart(255),
    id INT PRIMARY KEY,
    rnid INT
);"""

create_hg38 = """CREATE TABLE IF NOT EXISTS hg38 (
    hugo_symbol VARCHAR ( 255 ),
    gene_description VARCHAR ( 255 ),
    start_position INT,
    end_position INT,
    chromosome VARCHAR ( 50 ),
    gene_stable_id VARCHAR ( 155 ),
    gene_stable_id_version VARCHAR ( 155 ),
    id INT PRIMARY KEY,
);"""


create_dna_methylation = """CREATE TABLE IF NOT EXISTS methylation (
    pt_sbst_no VARCHAR (155),
    gene_name VARCHAR (155),
    target_id VARCHAR (155),
    target_type VARCHAR (25),
    gene_vl FLOAT,
    id INT,
    rnid INT
);"""

create_clinical_information = """CREATE TABLE IF NOT EXISTS clinical_information (
    pt_sbst_no VARCHAR ( 155 ),
    bmi_vl FLOAT,
    drnk_yn BOOLEAN,
    smok_curr_yn BOOLEAN,
    smok_yn BOOLEAN,
    diabetes_yn BOOLEAN,
    hyp_yn BOOLEAN,
    stage VARCHAR ( 155 ),
    t_category VARCHAR ( 10 ),
    n_category VARCHAR ( 155 ),
    sex_cd VARCHAR ( 155 ),
    diag_age INT,
    rlps_yn BOOLEAN,
    rlps_cnfr_drtn FLOAT,
    death_yn BOOLEAN,
    death_cnfr_drtn FLOAT,
    id INT PRIMARY KEY,
    rnid INT
);
"""

create_proteome = """CREATE TABLE IF NOT EXISTS proteome (
    pt_sbst_no VARCHAR ( 155 ),
    type VARCHAR (25),
    gene_name VARCHAR ( 155 ),
    p_name VARCHAR ( 155 ),
    gene_vl FLOAT,
    z_score FLOAT,
    id INT PRIMARY KEY,
    rnid INT
);"""


create_phospho = """CREATE TABLE IF NOT EXISTS phospho (
    pt_sbst_no VARCHAR ( 155 ),
    type VARCHAR (25),
    gene_name VARCHAR ( 155 ),
    site VARCHAR ( 155 ),
    gene_vl FLOAT,
    z_score FLOAT,
    id INT,
    rnid INT
);"""

create_rna_z_score = """CREATE TABLE IF NOT EXISTS rna(
    pt_sbst_no VARCHAR ( 155 ),
    gene_name VARCHAR ( 155 ),
    gene_vl FLOAT,
    z_score FLOAT,
    type VARCHAR (25),
    id INT PRIMARY KEY,
    rnid INT
);"""


create_cnv = """CREATE TABLE IF NOT EXISTS cnv(
    pt_sbst_no VARCHAR ( 155 ),
    chromosome VARCHAR ( 25 ),
    start_pos INT,
    end_pos INT,
    gene VARCHAR ( 55 ),
    log2 FLOAT,
    cn INT,
    depth FLOAT,
    probes INT,
    weight FLOAT,
    id INT,
    rnid INT,
    r_fk_id INT
);"""

create_fusion = """CREATE TABLE IF NOT EXISTS fusion(
left_gene_name VARCHAR ( 100 ),
left_gene_ensmbl_id VARCHAR ( 100 ),
left_gene_chr VARCHAR ( 100 ),
right_gene_name VARCHAR ( 100 ),
right_gene_ensmbl_id VARCHAR ( 100 ),
right_gene_chr VARCHAR ( 100 ),
pt_sbst_no VARCHAR ( 155 ),
left_hg38_pos INT,
right_hg38_pos INT,
junction_read_count INT,
spanning_frag_count INT,
splice_type VARCHAR ( 50 ),
id INT,
rnid INT
);"""


create_rnid = """CREATE TABLE IF NOT EXISTS rnid(
        id INT PRIMARY KEY,
        ybc_key varchar(100),
        rn_key varchar(100),
        brst_key varchar(100),
        dna_mutation_rnid BOOLEAN,
        methylation BOOLEAN,
        rnas BOOLEAN,
        phospho BOOLEAN,
        porteomes BOOLEAN,
        cnv_rnid BOOLEAN,
        fusion_gene BOOLEAN,
        total INT,
        image INT
    );"""
create_database = {
    "dna_mutation": create_dna_mutation,
    "methylation": create_dna_methylation,
    "rna": create_rna_z_score,
    "proteome": create_proteome,
    "clinical_information": create_clinical_information,
    "fusion": create_fusion,
    "cnv": create_cnv,
    "phospho": create_phospho,
    "rnid": create_rnid,
    "hg38": create_hg38,
}

all_integer_cols = [
    "RN36810877",
    "RN89646221",
    "RN33982492",
    "RN18703962",
    "RN88690962",
    "RN16228422",
    "RN95568707",
    "RN15613694",
    "RN83448490",
    "RN20588455",
    "RN06933750",
    "RN28269568",
    "RN89986459",
    "RN20573959",
    "RN98607622",
    "RN27277885",
    "RN44806340",
    "RN02133350",
    "RN68472676",
    "RN79754164",
    "RN46529037",
    "RN05791216",
    "RN23548716",
    "RN52308948",
    "RN86499633",
    "RN66159423",
    "RN43514740",
    "RN62053070",
    "RN80656698",
    "RN27134873",
    "RN56658174",
    "RN70413590",
    "RN85308965",
    "RN17178549",
    "RN02242105",
    "RN04685581",
    "RN02202045",
    "RN97371396",
    "RN04147073",
    "RN58654639",
    "RN76665056",
    "RN69645601",
    "RN05769486",
    "RN29433943",
    "RN83926344",
    "RN22241681",
    "RN82450207",
    "RN57508938",
    "RN71103191",
    "RN99939123",
    "RN34557618",
    "RN27673588",
    "RN62174206",
    "RN34173563",
    "RN73525036",
    "RN78915219",
    "RN10578326",
    "RN31625608",
    "RN17561557",
    "RN96132643",
    "RN98098427",
    "RN03686940",
    "RN96118654",
    "RN06641462",
    "RN65456541",
    "RN86410426",
    "RN26361868",
    "RN25665494",
    "RN82473577",
    "RN65007046",
    "RN44384516",
    "RN28210838",
    "RN15037234",
    "RN97102250",
    "RN40640584",
    "RN62729667",
    "RN72833229",
    "RN10281584",
    "RN06915040",
    "RN32721159",
    "RN66422546",
    "RN89206640",
    "RN53366503",
    "RN96745708",
    "RN77530888",
    "RN00334078",
    "RN44439642",
    "RN46085665",
    "RN98692058",
    "RN43116014",
    "RN82650850",
    "RN46339797",
    "RN55081633",
    "RN96772127",
    "RN84958322",
    "RN50151396",
    "RN37312989",
    "RN02849541",
    "RN94753745",
    "RN88777463",
    "RN98890277",
    "RN95593440",
    "RN69462918",
    "RN33931181",
    "RN22747800",
    "RN11453888",
    "RN30716975",
    "RN27642940",
]

all_proteome_cols = [
    "RN00334078",
    "RN00790493",
    "RN02133350",
    "RN02202045",
    "RN02242105",
    "RN02849541",
    "RN03014082",
    "RN03523019",
    "RN03686940",
    "RN04147073",
    "RN04685581",
    "RN05791216",
    "RN06641462",
    "RN06915040",
    "RN06933750",
    "RN10281584",
    "RN10578326",
    "RN11453888",
    "RN15037234",
    "RN16228422",
    "RN17178549",
    "RN17561557",
    "RN18703962",
    "RN20573959",
    "RN20588455",
    "RN22241681",
    "RN22747800",
    "RN23548716",
    "RN25665494",
    "RN26361868",
    "RN26604688",
    "RN27134873",
    "RN27277885",
    "RN27642940",
    "RN27673588",
    "RN28210838",
    "RN28269568",
    "RN29433943",
    "RN30716975",
    "RN31625608",
    "RN32721159",
    "RN33931181",
    "RN33982492",
    "RN34173563",
    "RN34557618",
    "RN36810877",
    "RN37312989",
    "RN39050568",
    "RN40640584",
    "RN43116014",
    "RN43514740",
    "RN44384516",
    "RN44439642",
    "RN44806340",
    "RN46085665",
    "RN46339797",
    "RN46529037",
    "RN50151396",
    "RN52308948",
    "RN52625958",
    "RN53366503",
    "RN55081633",
    "RN56658174",
    "RN57508938",
    "RN58654639",
    "RN59706094",
    "RN62053070",
    "RN62174206",
    "RN62729667",
    "RN65007046",
    "RN66159423",
    "RN66422546",
    "RN68065941",
    "RN68472676",
    "RN69462918",
    "RN69645601",
    "RN70413590",
    "RN71103191",
    "RN72833229",
    "RN76665056",
    "RN77530888",
    "RN79754164",
    "RN80656698",
    "RN82450207",
    "RN82650850",
    "RN83448490",
    "RN83926344",
    "RN84958322",
    "RN85308965",
    "RN86410426",
    "RN86499633",
    "RN87363744",
    "RN88690962",
    "RN88777463",
    "RN89206640",
    "RN89646221",
    "RN89986459",
    "RN94753745",
    "RN95038835",
    "RN95507927",
    "RN95568707",
    "RN95593440",
    "RN96118654",
    "RN96132643",
    "RN96745708",
    "RN96772127",
    "RN97102250",
    "RN97371396",
    "RN98098427",
    "RN98607622",
    "RN98692058",
    "RN98890277",
    "RN99939123",
]

filter_choices_column_names = {
    # "er_score": "ER Test",
    # "pr_score": "PR Test",
    "sex_cd": "sex",
    "diag_age": "Age Of Diaganosis",
    "bmi_vl": "Body Mass Index",
    # "bila_cncr_yn": "Diagnosis of Bilateral Breast Cancer",
    "smok_curr_yn": "Current Smoker",
    "smok_yn": "Former Smoker",
    "drnk_yn": "alcohol_consuption",
    "diabetes_yn": "Diabetes History",
    "hyp_yn": "Hypertension History",
    "stage": "Stage",
    # "meno_yn": "Menopause",
    # "delv_yn": "childbirth",
    # "feed_yn": "Experience of Breastfeeding",
    # "feed_drtn_mnth": "Duration of Breastfeeding (1-24 M)",
    # "oc_yn": "Intake of Oral Contraceptive Pill",
    # "hrt_yn": "Hormone Replacement Therapy",
    "t_category": "T Stage",
    "n_category": "N Stage",
    # "her2_score": "HER2 Score",
    # "ki67_score": "ki67",
    "rlps_cnfr_drtn": "Relapse Duration",
    "rlps_yn": "Relapse Yes or No",
}


oncoqueries = {
    # "smok_curr_yn": ["smok_yn", "smok_curr_yn"],
    # "feed_drtn_mnth": ["feed_drtn_year", "feed_drtn_mnth"],
}
onco_cusotom_queries = {
    # "er_score": "CASE when er_score='1' then 'Positive' when er_score='2' then 'Negative' END as er_score",
    # "pr_score": "CASE when pr_score='1' then 'Positive' when pr_score='2' then 'Negative' END as pr_score",
}
filter_type_numeric = {
    "bmi_vl": "number",
    # "mena_age": "number",
    # "feed_drtn_mnth": "number",
    # "ki67_score": "number",
    # "diag_age": "number",
}

table_types = {
    "dna_mutation": {
        "gene_name": "character",
        "sample_id": "character",
        "variant_classification": "character",
        "variant_type": "character",
        "chromosome": "character",
        "start_position": "numeric",
        "end_position": "numeric",
        "protein_change": "character",
        "swiss_prot_acc_id": "character",
        "annotation_transcript": "character",
        "gc_content": "decimal",
        "refseq_mrna_id": "character",
    },
    "rna": {
        "sample_id": "character",
        "gene_name": "character",
        "raw": "decimal",
        "norm": "decimal",
        "type": "character",
    },
    "clinical_information": {
        "sample_id": "character",
        "bmi_vl": "decimal",
        "rgst_ymd": "date",
        "drnk_yn": "yesorno",
        "smok_curr_yn": "yesorno",
        "smok_yn": "yesorno",
        "fmhs_brst_yn": "yesorno",
        "oc_yn": "yesorno",
        "hrt_yn": "yesorno",
        "mena_age": "decimal",
        "meno_yn": "yesorno",
        "delv_yn": "yesorno",
        "feed_yn": "yesorno",
        "feed_drtn_mnth": "decimal",
        "bila_cncr_yn": "yesorno",
        "rgst_dt": "character",
        "imnl_read_ymd": "date",
        "er_score": "numeric",
        "pr_score": "numeric",
        "her2_score": "character",
        "ki67_score": "numeric",
        "t_category": "character",
        "n_category": "character",
        "sex_cd": "character",
        "diag_age": "numeric",
        "rlps_yn": "yesorno",
        # "rlps_date": "date",
        "rlps_cnfr_drtn": "decimal",
        "death_yn": "yesorno",
        "death_cnfr_drtn": "decimal",
        "rnid": "numeric",
    },
    "methylation": {
        "sample_id": "character",
        "gene_name": "character",
        "target_id": "character",
        "target_type": "character",
        "gene_vl": "decimal",
    },
    "proteome": {
        "sample_id": "character",
        "type": "character",
        "gene_name": "character",
        "p_name": "character",
        "gene_vl": "decimal",
        "z_score": "decimal",
    },
    "phospho": {
        "sample_id": "character",
        "type": "character",
        "gene_name": "character",
        "site": "character",
        "z_score": "decimal",
        "gene_vl": "decimal",
    },
    "cnv": {
        "sample_id": "character",
        "chromosome": "character",
        "start_pos": "numeric",
        "end_pos": "numeric",
        "gene": "character",
        "log2": "decimal",
        "cn": "numeric",
        "depth": "decimal",
        "probes": "numeric",
        "weight": "decimal",
    },
    "fusion": {
        "sample_id": "character",
        "left_gene_name": "character",
        "left_gene_ensmbl_id": "character",
        "left_gene_chr": "character",
        "right_gene_name": "character",
        "right_gene_ensmbl_id": "character",
        "right_gene_chr": "character",
        "left_hg38_pos": "numeric",
        "right_hg38_pos": "numeric",
        "junction_read_count": "numeric",
        "spanning_frag_count": "numeric",
        "splice_type": "character",
    },
}

dna_mutation_variant_classifications_list = [
    "In_Frame_Ins",
    "In_Frame_Del",
    "Missense_Mutation",
    "Splice_Site",

    "Frame_Shift_Del",
    "Frame_Shift_Ins",
    "Nonsense_Mutation",
    "Germline",
]

variant_classifications_list = [
    "In_Frame_Ins",
    "mature_miRNA",
    "downstream_gene",
    "splice_acceptor",
    "non_coding_transcript_exon",
    "stop_retained",
    "In_Frame_Del",
    "5_prime_UTR",
    "coding_sequence",
    "Missense_Mutation",
    "splice_donor_5th_base",
    "3_prime_UTR",
    "intron",
    "protein_altering",
    "incomplete_terminal_codon",
    "upstream_gene",
    "synonymous",
    "NMD_transcript",
    "splice_donor_region",
    "Splice_Site",
    "splice_polypyrimidine_tract",
    "splice_donor",
    "frameshift",
    "stop_gained",
    "stop_lost",
    "start_lost",
    "non_coding_transcript"
]


def make_json(data):
    final_json = {}
    for cname in data:
        if cname[-3:] == "yes":
            index = cname.rfind("_")
            obj = {"key": cname[:index], "value": True, "bool": True}
            final_json[cname] = obj

        elif cname[-2:] == "no":
            index = cname.rfind("_")
            obj = {"key": cname[:index], "value": False, "bool": True}
            final_json[cname] = obj

        elif cname[0:4] == "from":
            index = cname.find("_")
            obj = {"key": cname[index + 1:], "value": True, "range": "from"}
            final_json[cname] = obj

        elif cname[0:2] == "to":
            index = cname.find("_")
            obj = {"key": cname[index + 1:], "value": True, "range": "to"}
            final_json[cname] = obj

        else:
            if cname != "filterCondition":
                index = cname.rfind("_")
                obj = {"key": cname[:index],
                       "value": f"{cname[index+1:]}", cname: True}
                final_json[cname] = obj

    return final_json


filterBoxes = {
    "sex_male": {"type": "checkbox", "name": "sex", "id": "sex_male", "value": "Male"},
    "sex_female": {
        "type": "checkbox",
        "name": "sex",
        "id": "sex_female",
        "value": "Female",
    },
    "from_aod": {"type": "number", "id": "aod", "value": "", "min": 20, "max": 40},
    "to_aod": {"type": "number", "id": "aod", "value": "", "min": 20, "max": 40},
    "from_bmi": {
        "type": "number",
        "id": "bmi",
        "value": "",
        "min": 15.82,
        "max": 36.33,
    },
    "to_bmi": {"type": "number", "id": "bmi", "value": "", "min": 15.82, "max": 36.33},
    # "from_fma": {
    #     "type": "number",
    #     "name": "fma",
    #     "id": "fma",
    #     "value": "",
    #     "min": 10,
    #     "max": 17,
    # },
    # "to_fma": {
    #     "type": "number",
    #     "name": "fma",
    #     "id": "fma",
    #     "value": "",
    #     "min": 10,
    #     "max": 17,
    # },
    # "from_dob": {
    #     "type": "number",
    #     "name": "dob",
    #     "id": "dob",
    #     "value": "",
    #     "min": 1,
    #     "max": 24,
    # },
    # "to_dob": {
    #     "type": "number",
    #     "name": "dob",
    #     "id": "dob",
    #     "value": "",
    #     "min": 1,
    #     "max": 24,
    # },
    # "from_turc": {
    #     "type": "number",
    #     "name": "turc",
    #     "id": "turc",
    #     "value": "",
    #     "min": 1,
    #     "max": 16,
    # },
    # "to_turc": {
    #     "type": "number",
    #     "name": "turc",
    #     "id": "turc",
    #     "value": "",
    #     "min": 1,
    #     "max": 16,
    # },
    # "from_ki67": {
    #     "type": "number",
    #     "name": "ki67",
    #     "id": "ki67",
    #     "value": "",
    #     "min": 1,
    #     "max": 95,
    # },
    # "to_ki67": {
    #     "type": "number",
    #     "name": "ki67",
    #     "id": "ki67",
    #     "value": "",
    #     "min": 1,
    #     "max": 95,
    # },
    # "dbbc_from": {
    #     "type": "checkbox",
    #     "name": "dbbc",
    #     "id": "dbbc_from",
    #     "value": "Yes",
    # },
    # "dbbc_to": {"type": "checkbox", "name": "dbbc", "id": "dbbc_to", "value": "No"},
    "current_smoker": {
        "type": "checkbox",
        "name": "smoking_status",
        "id": "current_smoker",
        "value": "Current Smoker",
    },
    "former_smoker": {
        "type": "checkbox",
        "name": "smoking_status",
        "id": "former_smoker",
        "value": "Past Smoker",
    },
    "non_smoker": {
        "type": "checkbox",
        "name": "smoking_status",
        "id": "non_smoker",
        "value": "Non Smoker",
    },
    "ac_yes": {
        "type": "checkbox",
        "name": "alcohol_consuption",
        "id": "ac_yes",
        "value": "Yes",
    },
    "ac_no": {
        "type": "checkbox",
        "name": "alcohol_consuption",
        "id": "ac_no",
        "value": "No",
    },
    # "fhbc_yes": {"type": "checkbox", "name": "fhbc", "id": "fhbc_yes", "value": "Yes"},
    # "fhbc_no": {"type": "checkbox", "name": "fhbc", "id": "fhbc_no", "value": "No"},
    # "menopause_yes": {
    #     "type": "checkbox",
    #     "name": "menopause",
    #     "id": "menopause_yes",
    #     "value": "Yes",
    # },
    # "menopause_no": {
    #     "type": "checkbox",
    #     "name": "menopause",
    #     "id": "menopause_no",
    #     "value": "No",
    # },
    # "childbirth_yes": {
    #     "type": "checkbox",
    #     "name": "childbirth",
    #     "id": "childbirth_yes",
    #     "value": "Yes",
    # },
    # "childbirth_no": {
    #     "type": "checkbox",
    #     "name": "childbirth",
    #     "id": "childbirth_no",
    #     "value": "No",
    # },
    # "eob_yes": {"type": "checkbox", "name": "eob", "id": "eob_yes", "value": "Yes"},
    # "eob_no": {"type": "checkbox", "name": "eob", "id": "eob_no", "value": "No"},
    # "iocp_yes": {"type": "checkbox", "name": "iocp", "id": "iocp_yes", "value": "Yes"},
    # "iocp_no": {"type": "checkbox", "name": "iocp", "id": "iocp_no", "value": "No"},
    "hyp_yes": {"type": "checkbox", "name": "hyp_yn", "id": "hyp_yes", "value": "Yes"},
    "hyp_no": {"type": "checkbox", "name": "hyp_yn", "id": "hyp_no", "value": "No"},
    "diabetes_yes": {"type": "checkbox", "name": "diabetes_yn", "id": "diabetes_yes", "value": "Yes"},
    "diabetes_no": {"type": "checkbox", "name": "diabetes_yn", "id": "diabetes_no", "value": "No"},
    # "tstage_is": {
    #     "type": "checkbox",
    #     "name": "tstage",
    #     "id": "tstage_is",
    #     "value": "Tis",
    # },
    "tstage_1": {
        "type": "checkbox",
        "name": "tstage",
        "id": "tstage_1",
        "value": "T1(1, 1a, 1b, 1c, 1mi)",
    },
    "tstage_2": {
        "type": "checkbox",
        "name": "tstage",
        "id": "tstage_2",
        "value": "T2(2)",
    },
    "tstage_3": {
        "type": "checkbox",
        "name": "tstage",
        "id": "tstage_3",
        "value": "T3(3)",
    },
    "tstage_4": {
        "type": "checkbox",
        "name": "tstage",
        "id": "tstage_4",
        "value": "T4(4b, 4d)",
    },
    # "nstage_nx": {
    #     "type": "checkbox",
    #     "name": "nstage",
    #     "id": "nstage_nx",
    #     "value": "Nx",
    # },
    "nstage_n0": {
        "type": "checkbox",
        "name": "nstage",
        "id": "nstage_n0",
        "value": "N0",
    },
    "nstage_n1": {
        "type": "checkbox",
        "name": "nstage",
        "id": "nstage_n1",
        "value": "N1(1mi, 1a, 1b)",
    },
    "nstage_n2": {
        "type": "checkbox",
        "name": "nstage",
        "id": "nstage_n2",
        "value": " N2(2, 2a)",
    },
    "nstage_n3": {
        "type": "checkbox",
        "name": "nstage",
        "id": "nstage_n3",
        "value": "N3(3, 3a)",
    },

    "stage_I": {
        "type": "checkbox",
        "name": "stage",
        "id": "stage_I",
        "value": "Stage I",
    },
    "stage_II": {
        "type": "checkbox",
        "name": "stage",
        "id": "stage_II",
        "value": "Stage II",
    },
    "stage_III": {
        "type": "checkbox",
        "name": "stage",
        "id": "stage_III",
        "value": "Stage III",
    },
    "stage_IV": {
        "type": "checkbox",
        "name": "stage",
        "id": "stage_IV",
        "value": "Stage IV",
    },
    # "etr_yes": {
    #     "type": "checkbox",
    #     "name": "etr",
    #     "id": "etr_yes",
    #     "value": "Positive",
    # },
    # "etr_no": {"type": "checkbox", "name": "etr", "id": "etr_no", "value": "Negative"},
    # "etr_na": {
    #     "type": "checkbox",
    #     "name": "etr",
    #     "id": "etr_na",
    #     "value": "Not evaluated",
    # },
    # "ptr_yes": {
    #     "type": "checkbox",
    #     "name": "ptr",
    #     "id": "ptr_yes",
    #     "value": "Positive",
    # },
    # "ptr_no": {"type": "checkbox", "name": "ptr", "id": "ptr_no", "value": "Negative"},
    # "ptr_na": {
    #     "type": "checkbox",
    #     "name": "ptr",
    #     "id": "ptr_na",
    #     "value": "Not evaluated",
    # },
    # "herscore_o": {
    #     "type": "checkbox",
    #     "name": "herscore",
    #     "id": "herscore_o",
    #     "value": "O",
    # },
    # "herscore_o1": {
    #     "type": "checkbox",
    #     "name": "herscore",
    #     "id": "herscore_o1",
    #     "value": "O~1+",
    # },
    # "herscore_1": {
    #     "type": "checkbox",
    #     "name": "herscore",
    #     "id": "herscore_1",
    #     "value": "1+",
    # },
    # "herscore_2": {
    #     "type": "checkbox",
    #     "name": "herscore",
    #     "id": "herscore_2",
    #     "value": "2",
    # },
    # "herscore_2+": {
    #     "type": "checkbox",
    #     "name": "herscore",
    #     "id": "herscore_2+",
    #     "value": "2+",
    # },
    # "herscore_3+": {
    #     "type": "checkbox",
    #     "name": "herscore",
    #     "id": "herscore_3+",
    #     "value": "3+",
    # },
    # "cr_yes": {"type": "checkbox", "name": "cr", "id": "cr_yes", "value": "Yes"},
    # "cr_no": {"type": "checkbox", "name": "cr", "id": "cr_no", "value": "No"},
}

advance_information_rows = [
    {"gene": "ATRX", "dna": "NO", "rna": "", "proteome": ""},
    {"gene": "BRAF", "dna": "NO", "rna": "", "proteome": ""},
    {"gene": "CDK4", "dna": "NO", "rna": "", "proteome": "HIGH"},
    {"gene": "CDK6", "dna": "NO", "rna": "", "proteome": "HIGH"},
    {"gene": "CDKN2A", "dna": "NO", "rna": "", "proteome": ""},
    {"gene": "CDKN2B", "dna": "NO", "rna": "", "proteome": ""},
    {"gene": "EGFR", "dna": "NO", "rna": "", "proteome": ""},
    {"gene": "FGFR1", "dna": "NO", "rna": "", "proteome": "LOW"},
    {"gene": "FGFR2", "dna": "NO", "rna": "", "proteome": ""},
    {"gene": "FGFR3", "dna": "NO", "rna": "", "proteome": ""},
    {"gene": "HRAS", "dna": "NO", "rna": "", "proteome": ""},
    {"gene": "IDH1", "dna": "NO", "rna": "", "proteome": ""},
    {"gene": "KRAS", "dna": "NO", "rna": "", "proteome": ""},
    {"gene": "MDM2", "dna": "NO", "rna": "", "proteome": ""},
    {"gene": "MDM4", "dna": "NO", "rna": "", "proteome": ""},
    {"gene": "MET", "dna": "NO", "rna": "", "proteome": ""},
    {"gene": "NF1", "dna": "NO", "rna": "", "proteome": ""},
    {"gene": "NRAS", "dna": "NO", "rna": "", "proteome": "HIGH"},
    {"gene": "PDGFRA", "dna": "NO", "rna": "", "proteome": ""},
    {"gene": "PIK3C2A", "dna": "NO", "rna": "", "proteome": "LOW"},
    {"gene": "PIK3C2G", "dna": "NO", "rna": "", "proteome": ""},
    {"gene": "PIK3CA", "dna": "NO", "rna": "", "proteome": ""},
    {"gene": "PIK3CG", "dna": "NO", "rna": "", "proteome": "HIGH"},
    {"gene": "PIK3R1", "dna": "NO", "rna": "", "proteome": "HIGH"},
    {"gene": "PIK3R2", "dna": "NO", "rna": "", "proteome": ""},
    {"gene": "PTEN", "dna": "NO", "rna": "", "proteome": ""},
    {"gene": "RB1", "dna": "NO", "rna": "", "proteome": ""},
    {"gene": "TP53", "dna": "YES", "rna": "", "proteome": ""},
]


def get_cox_object():
    cph = CoxPHFitter()
    return cph


def fetch_user_project_object(project_id):
    project_object = UserDataProjects.objects.get(id=project_id)
    available_steps = project_object.available_steps
    return available_steps


def generateOTP():

    # Declare a digits variable
    # which stores all digits
    AlphaNumerical = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    length = len(AlphaNumerical)
    OTP = ""

    # length of password can be changed
    # by changing value in range
    for i in range(6):
        OTP += AlphaNumerical[math.floor(random.random() * length)]

    return OTP


def downloadPDF(template_src, context_dict={}):

    template = get_template(template_src)
    html = template.render(context_dict)
    result = BytesIO()
    # pdf = pisa.pisaDocument(BytesIO(html.encode("ISO-8859-1")), result)
    if not pdf.err:
        return HttpResponse(result.getvalue(), content_type="application/pdf")
    return None


def filter_query_formater(data, circos=False):
    query_string = {}
    table_name = "clinical_information"
    filter_condition = data["filterCondition"]
    for key, val in data.items():
        field = advance_filter_fields.get(key)
        if field is None:
            continue
        column_name = advance_filter_fields[key]["key"]
        if column_name not in query_string:
            query_string[column_name] = []
        column_value = val
        if field.get("range"):
            if column_name == "ki67_score":
                column_value = f"{val}"
            if field["range"] == "to":
                query_string[column_name].append(
                    f" {table_name}.{column_name} <= {column_value}"
                )
            else:
                query_string[column_name].append(
                    f" {table_name}.{column_name} >= {column_value}"
                )
        elif field.get("bool"):
            if field.get("value"):
                query_string[column_name].append(
                    f" {table_name}.{column_name} = 'Y'")
            else:
                query_string[column_name].append(
                    f" {table_name}.{column_name} = 'N'")
        elif field.get("custom"):
            query_string[column_name].append(
                f"{table_name}.{column_name} = {advance_filter_fields[key]['value']}"
            )
        elif (field.get("t_category") == True) or field.get("n_category") == True:
            category_value = advance_filter_fields[key]["value"]
            if type(category_value) == str:
                query_string[column_name].append(
                    f"{table_name}.{column_name}='{category_value}'"
                )
            else:
                category_value_str = "','".join(category_value)
                query_string[column_name].append(
                    f"{table_name}.{column_name} in ('{category_value_str}')"
                )
        else:
            query_string[column_name].append(
                f" {table_name}.{column_name} = '{advance_filter_fields[key]['value']}'"
            )

    q = []
    for k, v in query_string.items():
        if k in filter_type_numeric:
            t = " and ".join(v)
        else:
            t = " or ".join(v)
        q.append(f"( {t} )")
    if circos:
        tmp = f" {filter_condition} ".join(q) if q else ""
        return tmp, len(q) > 0

    temp = f" {filter_condition} ".join(q) if q else ""
    return temp


def orm_filter_query_formater(data, circos=False):
    query_string = {}
    params = []
    table_name = "clinical_information"
    filter_condition = data["filterCondition"]

    for key, val in data.items():
        field = advance_filter_fields.get(key)
        if field is None:
            continue
        column_name = advance_filter_fields[key]["key"]
        if column_name not in query_string:
            query_string[column_name] = []
        column_value = val
        if field.get("range"):
            if column_name == "ki67_score":
                column_value = f"{val}"
            if field["range"] == "to":
                query_string[column_name].append(
                    f" {table_name}.{column_name} <= %s")
            else:
                query_string[column_name].append(
                    f" {table_name}.{column_name} >= %s")
            params.append(column_value)
        elif field.get("bool"):
            if field.get("value"):
                query_string[column_name].append(
                    f" {table_name}.{column_name} = 'Y'")
            else:
                query_string[column_name].append(
                    f" {table_name}.{column_name} = 'N'")
        elif field.get("custom"):
            query_string[column_name].append(
                f"{table_name}.{column_name} = %s")
            value_is = (
                advance_filter_fields[key]["value"][1:-1]
                if key == "sex_male" or key == "sex_female"
                else advance_filter_fields[key]["value"]
            )
            params.append(value_is)

        elif (field.get("t_category") == True) or field.get("n_category") == True:
            category_value = advance_filter_fields[key]["value"]
            if type(category_value) == str:
                query_string[column_name].append(
                    f"{table_name}.{column_name}= %s")
                params.append(category_value)
            else:
                category_value_str = "','".join(category_value)
                query_string[column_name].append(
                    f"{table_name}.{column_name} in ('{category_value_str}')"
                )
        else:
            query_string[column_name].append(
                f" {table_name}.{column_name} = %s")
            params.append(advance_filter_fields[key]["value"])

    q = []
    for k, v in query_string.items():
        if k in filter_type_numeric:
            t = " and ".join(v)
        else:
            t = " or ".join(v)
        q.append(f"( {t} )")
    if circos:
        tmp = f" {filter_condition} ".join(q) if q else ""
        return tmp, params, len(q) > 0
    tmp = f" {filter_condition} ".join(q) if q else ""
    return tmp, params


def advance_filter_query_formater(data, circos=False, project_id=None):

    filter_condition = data["filterCondition"]
    query_string = {}

    if project_id is None:
        return Response(status=204)
    project_information = UserDataProjects.objects.get(id=project_id)
    database_path = project_information.sql_path
    columns_in_db = {}
    try:
        project_database = {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": database_path,
            "ATOMIC_REQUESTS": False,
            "AUTOCOMMIT": True,
            "CONN_MAX_AGE": 0,
            "OPTIONS": {},
            "TIME_ZONE": None,
            "USER": "",
            "PASSWORD": "",
            "HOST": "",
            "PORT": "",
            "TEST": {
                "CHARSET": None,
                "COLLATION": None,
                "MIGRATE": True,
                "MIRROR": None,
                "NAME": None,
            },
        }
        settings.DATABASES["userdata"] = project_database
        conn = sql.connect(database_path)
        table_name = "clinical_information"
        query = f"PRAGMA table_info('{table_name}')"
        cursor = conn.execute(query)
        res = cursor.fetchall()
        for cname in res:
            if cname[1] != "id" and cname[1] != "rnid":
                columns_in_db[cname[1]] = cname[2]

        final_json = make_json(data)
        range_list = []

        for key, val in data.items():
            field = final_json.get(key)

            if field is None:
                continue
            column_name = final_json[key]["key"]
            if column_name not in query_string:
                query_string[column_name] = []
            column_value = val
            if field.get("range"):
                range_list.append(column_name)
                if field["range"] == "to":
                    query_string[column_name].append(
                        f" {table_name}.{column_name} <= {column_value}"
                    )
                else:
                    query_string[column_name].append(
                        f" {table_name}.{column_name} >= {column_value}"
                    )
            elif field.get("bool"):
                if field.get("value"):
                    query_string[column_name].append(
                        f" {table_name}.{column_name} = '1' "
                    )
                else:
                    query_string[column_name].append(
                        f" {table_name}.{column_name} = '0' "
                    )
            elif field.get("custom"):
                query_string[column_name].append(
                    f"{table_name}.{column_name} = {final_json[key]['value']}"
                )
            elif (field.get("t_category") == True) or field.get("n_category") == True:
                category_value = final_json[key]["value"]
                if type(category_value) == str:
                    query_string[column_name].append(
                        f"{table_name}.{column_name}='{category_value}'"
                    )
                else:
                    category_value_str = "','".join(category_value)
                    query_string[column_name].append(
                        f"{table_name}.{column_name} in ('{category_value_str}')"
                    )
            else:
                query_string[column_name].append(
                    f" {table_name}.{column_name} = '{final_json[key]['value']}'"
                )

        q = []
        for k, v in query_string.items():
            if k in range_list:
                t = " and ".join(v)
            else:
                t = " or ".join(v)
            q.append(f"( {t} )")

        if circos:
            tmp = f" {filter_condition} ".join(q) if q else ""
            return tmp, len(q) > 0

        return f" {filter_condition} ".join(q) if q else ""

    except Exception as e2:
        print("e2", e2)


def orm_advance_filter_query_formater(data, circos=False, project_id=None):
    filter_condition = data["filterCondition"]
    query_string = {}
    params = []
    if project_id is None:
        return Response(status=204)
    project_information = UserDataProjects.objects.get(id=project_id)
    database_path = project_information.sql_path
    columns_in_db = {}
    try:
        project_database = {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": database_path,
            "ATOMIC_REQUESTS": False,
            "AUTOCOMMIT": True,
            "CONN_MAX_AGE": 0,
            "OPTIONS": {},
            "TIME_ZONE": None,
            "USER": "",
            "PASSWORD": "",
            "HOST": "",
            "PORT": "",
            "TEST": {
                "CHARSET": None,
                "COLLATION": None,
                "MIGRATE": True,
                "MIRROR": None,
                "NAME": None,
            },
        }
        settings.DATABASES["userdata"] = project_database
        conn = sql.connect(database_path)
        table_name = "clinical_information"
        query = f"PRAGMA table_info('{table_name}')"
        cursor = conn.execute(query)
        res = cursor.fetchall()
        for cname in res:
            if cname[1] != "id" and cname[1] != "rnid":
                columns_in_db[cname[1]] = cname[2]

        final_json = make_json(data)
        range_list = []

        for key, val in data.items():
            field = final_json.get(key)

            if field is None:
                continue
            column_name = final_json[key]["key"]
            if column_name not in query_string:
                query_string[column_name] = []
            column_value = val
            if field.get("range"):
                range_list.append(column_name)
                if field["range"] == "to":
                    query_string[column_name].append(
                        f" {table_name}.{column_name} <= %s"
                    )
                else:
                    query_string[column_name].append(
                        f" {table_name}.{column_name} >= %s"
                    )
                params.append(column_value)
            elif field.get("bool"):
                if field.get("value"):
                    query_string[column_name].append(
                        f" {table_name}.{column_name} = '1' "
                    )
                else:
                    query_string[column_name].append(
                        f" {table_name}.{column_name} = '0' "
                    )
            elif field.get("custom"):
                query_string[column_name].append(
                    f"{table_name}.{column_name} = %s")
                params.append(final_json[key]["value"])

            elif (field.get("t_category") == True) or field.get("n_category") == True:
                category_value = final_json[key]["value"]
                if type(category_value) == str:
                    query_string[column_name].append(
                        f"{table_name}.{column_name}= %s")
                    params.append(category_value)
                else:
                    # Needs to be checked
                    category_value_str = "','".join(category_value)
                    query_string[column_name].append(
                        f"{table_name}.{column_name} in ('{category_value_str}')"
                    )
            else:
                query_string[column_name].append(
                    f" {table_name}.{column_name} = %s")
                params.append(final_json[key]["value"])

        q = []
        for k, v in query_string.items():
            if k in range_list:
                t = " and ".join(v)
            else:
                t = " or ".join(v)
            q.append(f"( {t} )")

        if circos:
            tmp = f" {filter_condition} ".join(q) if q else ""
            return tmp, params, len(q) > 0

        tmp = f" {filter_condition} ".join(q) if q else ""
        return tmp, params

    except Exception as e2:
        print("e2", e2)


def analyse_clinical_information(file_path):
    df = pd.read_csv(file_path, delimiter="\t")

    data_types = {}
    error_dict = {}
    is_error = False

    for column in df.columns:
        column_values = df[column].dropna()
        original_row_numbers = df[column].dropna().index.tolist()

        type_counts = {"numeric": 0, "decimal": 0,
                       "yesorno": 0, "character": 0}
        type_rows = {
            "numeric_rows": [],
            "decimal_rows": [],
            "yesorno_rows": [],
            "character_rows": [],
        }

        for row_number, value in zip(original_row_numbers, column_values):
            value = str(value)
            if isinstance(value, int):
                type_counts["numeric"] += 1
                type_rows["numeric_rows"].append(row_number)
            elif isinstance(value, float):
                if value.is_numeric():
                    type_counts["numeric"] += 1
                    type_rows["numeric_rows"].append(row_number)
                else:
                    type_counts["decimal"] += 1
                    type_rows["decimal_rows"].append(row_number)
            elif isinstance(value, bool):
                type_counts["yesorno"] += 1
                type_rows["yesorno_rows"].append(row_number)
            elif isinstance(value, str):
                if value.strip() != "":
                    if value.lower() in ["true", "false"]:
                        type_counts["yesorno"] += 1
                        type_rows["yesorno_rows"].append(row_number)
                    else:
                        try:
                            int(value)
                            type_counts["numeric"] += 1
                            type_rows["numeric_rows"].append(row_number)
                        except ValueError:
                            try:
                                float(value)
                                type_counts["decimal"] += 1
                                type_rows["decimal_rows"].append(row_number)
                            except ValueError:
                                type_counts["character"] += 1
                                type_rows["character_rows"].append(row_number)

        # Check if any values in the column don't match the majority key
        error_dict[column] = {}
        majority_key = max(type_counts, key=type_counts.get)
        for key, row_numbers in type_rows.items():
            if key != majority_key + "_rows":
                expected_type = majority_key.capitalize()
                current_type = key[:-5].capitalize()
                if row_numbers:
                    error_rows = ", ".join(map(str, row_numbers))
                    error_message = f"Expected {expected_type}, but got {current_type} in rows: {error_rows}"
                    error_dict[column]['type1'] = True
                    error_dict[column]['error_rows'] = error_rows
                    error_dict[column]['error_message'] = error_message
                    error_dict[column]['expected_type'] = expected_type
                    error_dict[column]['current_type'] = current_type

        # Determine the data type of the column
        if majority_key == "character":
            column_data_type = "character"
            error_dict[column] = {}
        elif majority_key == "yesorno":
            column_data_type = "yesorno"
        elif sum(value > 0 for value in type_counts.values()) >= 2:
            column_data_type = "mixed"
            is_error = True
        else:
            column_data_type = majority_key

        data_types[column] = column_data_type

        # Check if a character column has more than 5 unique values
        if (
            majority_key == "character"
            and column != "sample_id"
            and len(df[column].unique()) > 5
        ):
            error_message = f"The column '{column}' has more than 5 unique values"
            error_dict[column]['type2'] = True
            error_dict[column]['error_message'] = error_message

        if not error_dict[column]:
            del error_dict[column]
    return data_types, error_dict, is_error

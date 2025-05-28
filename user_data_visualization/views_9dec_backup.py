import os
import random
import shutil
import logging
import sqlite3 as sql
from datetime import datetime
import threading
import numpy as np
import pandas as pd
import time
from rest_framework.decorators import api_view
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import permissions
from django.db.models import Q
from django.conf import settings
from django.utils import timezone
from django.utils.timezone import now
from django.core.paginator import Paginator
from django.utils.decorators import method_decorator
from django.core.files.storage import default_storage
from django.core.exceptions import ObjectDoesNotExist,SuspiciousFileOperation
from django.db.utils import DatabaseError,IntegrityError
from django.http import HttpResponseServerError
from django.views.decorators.csrf import csrf_protect, csrf_exempt
from django.contrib.auth import get_user_model
from app.models import ClinicalInformation
import uuid
from app.constants import (
    create_database,
    int_converter_,
    str_converter,
    float_converter,
    bool_converter,
    table_types,
    visualization_tables_requirement,
    analyse_clinical_information,
    add_line_in_logger_file
)
from .serializers import (
    UserDataProjectsSerializer,
    UserDataProjectsGetSerializer,
    ProjectDataSerializer,
    UserDataExtensionSerializer
)
from .models import UserDataProjects, UserDataExtension


User = get_user_model()

logger = logging.getLogger(__name__)

def validate(columns, filetype):
    """
    Validate the provided columns against required column names based on the file type.

    This function validates the provided list of columns against the required column names
    for a specific file type (e.g., clinical information, DNA mutation, RNA, etc.). It ensures
    that the correct columns are present and that their count matches the expected count for
    the given file type.

    Args:
        columns (list): A list of column names to be validated.
        filetype (str): The type of file for which validation is performed.

    Returns:
        dict: A dictionary containing validation results and messages.
            - "message" (str): A message indicating the validation result or error.
            - "status" (int): The status code representing the validation outcome.
            - "finalcolumns" (list): A list of columns validated against the required columns.

    Example:
        validation_result = validate(["sample_id", "gene_name", "norm", "raw", "type"], "rna")
        Example output: {"message": "",
                         "status": 200,
                         "finalcolumns": ["gene_name", "sample_id", "norm", "raw", "type"]
                        }
    """
    validate_column_names = {
        "clinical_information": [
            "sample_id",
            "rlps_yn",
            "rlps_cnfr_drtn",
            "death_yn",
            "death_cnfr_drtn",
        ],
        "dna_mutation": [
            "gene_name",
            "sample_id",
            "variant_classification",
            "variant_type",
            "chromosome",
            "start_position",
            "end_position",
            "protein_change",
            "swiss_prot_acc_id",
            "annotation_transcript",
            "gc_content",
            "refseq_mrna_id",
        ],
        "rna": ["gene_name", "sample_id", "norm", "raw", "type"],
        "methylation": [
            "sample_id",
            "gene_name",
            "target_id",
            "target_type",
            "gene_vl",
        ],
        "proteome": ["sample_id", "type", "gene_name", "p_name", "gene_vl", "z_score"],
        "phospho": ["sample_id", "type", "gene_name", "site", "gene_vl", "z_score"],
        "fusion": [
            "sample_id",
            "left_gene_name",
            "left_gene_ensmbl_id",
            "left_gene_chr",
            "right_gene_name",
            "right_gene_ensmbl_id",
            "right_gene_chr",
            "left_hg38_pos",
            "right_hg38_pos",
            "junction_read_count",
            "spanning_frag_count",
            "splice_type",
        ],
        "cnv": [
            "sample_id",
            "chromosome",
            "start_pos",
            "end_pos",
            "gene",
            "log2",
            "cn",
            "depth",
            "probes",
            "weight",
        ],
    }
    message = ""
    status = 200
    finalcolumns = []
    count = 0
    for columname in columns:
        if filetype == "clinical_information":
            if columname in validate_column_names[filetype]:
                count = count + 1
                continue
        else:
            if columname in validate_column_names[filetype]:
                finalcolumns.append(columname)
            else:
                message = "Please insert all the columns that are required, \
                    Click on the Help Icon to see the required columns"
                finalcolumns = []
                status = 204
                break
            if not (
                set(columns) == set(validate_column_names[filetype])
                and len(columns) == len(validate_column_names[filetype])
            ):
                message = "Please insert all the columns that are required, \
                    Click on the Help Icon to see the required columns"
                finalcolumns = []
                status = 204
                break
    if (filetype == "clinical_information") and (count < 5):
        message = "Please insert all the Mandatory columns, \
            Click on the Help Icon to see the required columns"
        status = 204
    return {"message": message, "status": status, "finalcolumns": finalcolumns}

#@method_decorator(csrf_protect, name="dispatch")
class NewUserDataVisualization(APIView):
    """
    API view for uploading and processing new user data visualizations.

    This view handles the upload and processing of various types of data files
    for generating visualizations. It supports both single and multi-file upload modes.
    The uploaded files are validated and processed to ensure they meet the required criteria.

    Attributes:
        permission_classes (tuple): Tuple containing permission classes,
        requires user authentication.

    Methods:
        change_file_name(filename): Generate a random filename with the original file's extension.
        post(request): Handle the POST request for uploading and processing files.

    """
    permission_classes = (permissions.IsAuthenticated,)

    def change_file_name(self, filename):
        """
        Generate a random filename with the original file's extension.

        Args:
            filename (str): Original filename.

        Returns:
            str: New random filename with the original file's extension.
        """
        _, file_extension = os.path.splitext(filename)
        chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890"
        randomstr = "".join((random.choice(chars)) for _ in range(10))
        return f"{randomstr}{file_extension}"

    def post(self, request):
        """
        Handle the POST request for uploading and processing files.

        This method processes the uploaded files, validates their contents, and
        performs necessary operations to prepare them for visualization generation.

        Args:
            request (HttpRequest): The HTTP request object containing uploaded files and data.

        Returns:
            Response: A JSON response indicating the success or any errors during processing.
        """

        try:
            is_error = False
            username = self.request.user.username
            project_name = request.data["project_name"]
            project_name = project_name.replace(" ", "_")
            user_project_directory = f"{settings.BASE_DIR}/media/{username}"
            user_files_directory = os.path.join(user_project_directory, "files")
            user_db_directory = os.path.join(user_project_directory, "database")
            viz_type = ""
            if request.path == "/k-corev/single-new-user-data-visualization/":
                viz_type = "single"
            else:
                viz_type = "multi"

            if not os.path.exists(user_project_directory):
                os.makedirs(user_project_directory)
            if not os.path.exists(user_files_directory):
                os.makedirs(user_files_directory)
            if not os.path.exists(user_db_directory):
                os.makedirs(user_db_directory)

            res = []
            if viz_type == 'multi':
                file_count = len(request.FILES)
                if 'mutation_file_name' in request.data:
                    file_count += 1
                if file_count < 2:
                    return Response(
                        {
                            "res": res,
                            "issue": "Please upload at least two files",
                            "project_name": project_name,
                            "status": 500,
                        }
                    )
            for user_file_object in request.FILES:
                tmp = {}
                file_data = request.FILES[user_file_object]
                file_name = file_data.name
                filepath = os.path.join(user_files_directory, file_name)
                default_storage.save(filepath, file_data)

                changed_name = self.change_file_name(file_data.name)
                changed_file_path = os.path.join(
                    user_files_directory, changed_name)
                os.rename(filepath, changed_file_path)

                filepath = changed_file_path
                tmp["filename"] = changed_name
                tmp["filepath"] = filepath
                tmp["tab"] = user_file_object
                row_number = 0
                issue = "allFileColumns1"
                with open(filepath, "r") as file:
                    for each in file:
                        row = each.split("\t")
                        if row_number == 0:
                            length_of_columns = len(row)
                            columns = [e.strip() for e in row]
                            if (
                                user_file_object == "clinical_information"
                            ) and length_of_columns <= 17:
                                column_validation = validate(
                                    columns, user_file_object)
                                if column_validation["status"] == 200:
                                    tmp["columns"] = columns
                                    tmp["message"] = ""
                                    tmp["types"] = table_types[user_file_object]
                                else:
                                    is_error = True
                                    tmp["columns"] = []
                                    tmp["message"] = column_validation["message"]
                                    tmp["types"] = table_types[user_file_object]

                            elif user_file_object == "clinical_information" and length_of_columns > 17:
                                is_error = True
                                tmp["columns"] = []
                                tmp["message"] = "Clinical Information File should have less\
                                    than or equal to 17 columns, more than 17 found"
                                issue = "allFileColumns2"

                            elif user_file_object != "clinical_information":
                                column_validation = validate(
                                    columns, user_file_object)
                                if column_validation["status"] == 200:
                                    tmp["columns"] = column_validation["finalcolumns"]
                                    tmp["message"] = ""
                                    tmp["types"] = table_types[user_file_object]
                                else:
                                    is_error = True
                                    tmp["columns"] = []
                                    tmp["message"] = column_validation["message"]
                            else:
                                is_error = True
                                tmp["columns"] = []
                                tmp["message"] = "Error: Please Read Instructions"
                                issue = "allFileColumns3"
                            break
                res.append(tmp)

            file_types = {}
            if not is_error:
                for item in res:
                    tab = item["tab"]
                    filename = item["filename"]
                    types = {}
                    if tab != "clinical_information":
                        types = item["types"]
                    elif tab == "clinical_information":
                        types, errors, is_clinical_error = analyse_clinical_information(
                            item["filepath"]
                        )
                        if is_clinical_error:
                            delete_user_files(user_files_directory)
                            return Response(
                                {
                                    "res": res,
                                    "issue": "clinicalInforamtionFile",
                                    "clinicalRows": errors,
                                    "project_name": project_name,
                                    "status": 200,
                                }
                            )

                    if tab not in file_types:
                        file_types[tab] = {"tab": tab,
                                        "filename": filename, "types": types}
                    else:
                        file_types[tab]["filename"] = filename

            else:
                delete_user_files(user_files_directory)
                return Response(
                    {
                        "res": res,
                        "issue": "allFileColumns",
                        "specific_issue":issue,
                        "project_name": project_name,
                        "status": 200,
                    }
                )
            verify_view = VerifyClinicalDataColumns()

            #### Call the post method of VerifyClinicalDataColumns
            arguments = {"project_name": project_name}
            arguments["file_types"] = file_types
            arguments["viz_type"] = viz_type

            response = verify_view.post(
                request._request,
                **arguments,
            )
            if response:
                response_data = response.data
                if response_data.get('status') is True:
                    if response_data.get('message')=='' and response_data.get('issue')=='':
                        file_exists = response_data.get('file_exists')
                        project_id = response_data.get('project_id')
                        project_name = response_data.get('project_name')
                        if viz_type == 'multi':
                            ext_object = UserDataExtension(
                                        username=username,
                                        project_name=project_name,
                                        project_id=project_id,
                                        files=file_exists,
                                        id=project_id
                                    )
                            ext_object.save()
                            ext_serializer = UserDataExtensionSerializer(
                                ext_object, data=file_exists, partial=True
                            )
                            if ext_serializer.is_valid():
                                ext_serializer.save()

                        return response
                    elif response_data.get('issue')!='':
                        last_project = UserDataProjects.objects.all().order_by('-id').first()
                        if last_project:
                            if viz_type == 'multi':
                                last_project.delete()
                        # delete_user_files(user_files_directory)
                        return response


                return Response(
                    {
                        "res": response_data.get('result'),
                        "message": response_data.get('message'),
                        "issue": response_data.get('issue'),
                        "project_name": project_name,
                        "status": response_data.get('status'),
                    }
                )

        except (ObjectDoesNotExist, DatabaseError, IntegrityError, FileNotFoundError) as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")


@method_decorator(csrf_protect, name="dispatch")
class VerifyClinicalDataColumns(APIView):
    """
    API view for verifying and processing clinical data columns.

    This view handles the verification and processing of clinical data columns
    uploaded by users. It validates the contents of the columns, checks for data
    integrity, and prepares the data for visualization generation.

    Methods:
        post(request, **args): Handle the POST request for verifying and processing columns.
    """

    def post(self, request, **args):
        """
        Handle the POST request for verifying and processing columns.

        This method performs verification and processing of the uploaded clinical data columns.
        It checks the data integrity,
        validates the column types,
        and prepares the data for visualization.

        Args:
            request (HttpRequest): The HTTP request object containing column data.
            **args: Additional arguments containing information about the uploaded files and data.

        Returns:
            Response: A JSON response indicating the verification status and processed data.
        """
        try:
            maincolumns = args if args else request.data
            first_failure = True
            result = {}
            charectercount = {}
            charectercountcolumns = set([])
            username = request.user.username if args else self.request.user.username
            viz_type = ""
            if args:
                viz_type = args["viz_type"]
            success = False
            sample_ids = {}
            message = ""
            column_messages = {}
            project_data = {}
            is_clinical = (
                True if "clinical_information" in maincolumns["file_types"] else False
            )

            project_uuid = str(maincolumns["project_id"])
            project_object = UserDataProjects.objects.get(project_id=project_uuid)

            project_object.is_clinical=is_clinical
            project_object.save()


            clinical_default_columns = [
                "sample_id",
                "rlps_yn",
                "rlps_cnfr_drtn",
                "death_yn",
                "death_cnfr_drtn",
            ]
            clinical_default_types = {
                "sample_id": "character",
                "rlps_yn": "yesorno",
                "rlps_cnfr_drtn": "decimal",
                "death_yn": "yesorno",
                "death_cnfr_drtn": "decimal",
            }

            error_rows = {}
            mutation_type = request.POST.get("mutation_type",None)
            mutation_file_name = request.POST.get("mutation_file_name",None)
            # Step 1 -Checking the each row datatypes and adding results and error
            # objects and samples for each files
            latest_project_id = 0
            if mutation_type == 'maf':
                os.system(f"cp -r {settings.BASE_DIR}/media/MAFMerger/{username}/{mutation_file_name} {settings.BASE_DIR}/media/{username}/files/{mutation_file_name}")
                filepath = f"{settings.BASE_DIR}/media/{username}/files/{mutation_file_name}"
                filename = "dna_mutation"
                key ='dna_mutation'
                maincolumns['file_types']['dna_mutation'] = {'tab':'dna_mutation','filename':mutation_file_name}

            for _, (key, value) in enumerate(maincolumns["file_types"].items()):
                filename = value["filename"]
                if mutation_type=='maf' and key=='dna_mutation':
                    filepath = f"{settings.BASE_DIR}/media/{username}/files/{mutation_file_name}"
                    filename = mutation_file_name
                filepath = f"{settings.BASE_DIR}/media/{username}/files/{filename}"
                filecolumns = []
                row_num = 0
                error_row_num = 0
                sample_ids[key] = []
                print(f'key= {key}')
                print(f'value["filename"]= {value["filename"]}')

                try:
                    with open(filepath, "r") as file_:
                        result[filename] = []
                        error_rows[filename] = []
                        for each in file_:
                            row_is_error = False
                            row = each.split("\t")
                            row = [er.strip() for er in row]

                            if row_num == 0:
                                row_num = row_num + 1
                                error_row_num = error_row_num + 1
                                columns = [er.strip() for er in row]
                                filecolumns = columns
                                result[filename].append(
                                    {"columns": columns, "tab": key})
                                error_rows[filename].append(
                                    {"columns": columns, "tab": key, "is_error": False}
                                )
                            elif row_num > 0:
                                rowobject = {row_num: {}}
                                errorobject = {error_row_num: {}}
                                for idx, _ in enumerate(row):
                                    columnname = filecolumns[idx]
                                    if value["tab"] != "clinical_information":
                                        columntype = table_types[key][columnname]
                                    else:
                                        columntype = value["types"][columnname]

                                    if columntype == "numeric":
                                        if not key in column_messages:
                                            column_messages[key] = {}
                                        if not columnname in column_messages[key]:
                                            column_messages[key][columnname] = ""

                                        if (
                                            row[idx] is not None
                                            and row[idx] != ""
                                            and row[idx].isnumeric() == False
                                            and len(row[idx]) == 0
                                        ):
                                            rowobject[row_num][columnname] = {
                                                "value": row[idx],
                                                "success": "False",
                                                "message": "expected Integer value",
                                                "expected": "Integer"
                                            }
                                            errorobject[error_row_num][columnname] = {
                                                "row": row_num,
                                                "value": row[idx],
                                                "success": "False",
                                                "message": "expected Integer value",
                                                "expected": "Integer"
                                            }
                                            first_failure = False
                                            column_messages[key][columnname] = "expected Integer value but found something else"
                                            row_is_error = True
                                            success = False
                                        else:
                                            num = int_converter_(row[idx])
                                            if num is not None:
                                                rowobject[row_num][columnname] = {
                                                    "value": int_converter_(row[idx]),
                                                    "success": "True",
                                                    "message": "",
                                                    "expected": ""
                                                }
                                                errorobject[error_row_num][columnname] = {
                                                    "row": row_num,
                                                    "value": int_converter_(row[idx]),
                                                    "success": "True",
                                                    "message": "",
                                                    "expected": ""
                                                }
                                                success = True
                                            elif num is None and row[idx] == "":
                                                rowobject[row_num][columnname] = {
                                                    "value": row[idx],
                                                    "success": "True",
                                                    "message": "",
                                                    "expected": ""
                                                }
                                                errorobject[error_row_num][columnname] = {
                                                    "row": row_num,
                                                    "value": int_converter_(row[idx]),
                                                    "success": "True",
                                                    "message": "",
                                                    "expected": ""
                                                }
                                                success = True
                                            else:
                                                rowobject[row_num][columnname] = {
                                                    "value": row[idx],
                                                    "success": "False",
                                                    "message": "expected Integer value",
                                                    "expected": "Integer"
                                                }
                                                errorobject[error_row_num][columnname] = {
                                                    "row": row_num,
                                                    "value": row[idx],
                                                    "success": "False",
                                                    "message": "expected Integer value",
                                                    "expected": "Integer"
                                                }
                                                first_failure = False
                                                column_messages[key][
                                                    columnname
                                                ] = "expected Integer value but found something else"
                                                row_is_error = True
                                                success = False
                                    elif columntype == "decimal":
                                        if not key in column_messages:
                                            column_messages[key] = {}
                                        if not columnname in column_messages[key]:
                                            column_messages[key][columnname] = ""
                                        if (
                                            row[idx] is not None
                                            and row[idx] != ""
                                            and float_converter(row[idx]) == True
                                        ):
                                            try:
                                                rowobject[row_num][columnname] = {
                                                    "value": float(row[idx]),
                                                    "success": "True",
                                                    "message": "",
                                                    "expected": ""
                                                }
                                                errorobject[error_row_num][columnname] = {
                                                    "row": row_num,
                                                    "value": float(row[idx]),
                                                    "success": "True",
                                                    "message": "",
                                                    "expected": ""
                                                }
                                                success = True
                                            except BaseException:
                                                rowobject[row_num][columnname] = {
                                                    "value": row[idx],
                                                    "success": "False",
                                                    "message": "expected Decimal value",
                                                    "expected": "Decimal"
                                                }
                                                errorobject[error_row_num][columnname] = {
                                                    "row": row_num,
                                                    "value": row[idx],
                                                    "success": "False",
                                                    "message": "expected Decimal value",
                                                    "expected": "Decimal"
                                                }
                                                column_messages[key][columnname] = "expected Decimal value but found something else"
                                                first_failure = False
                                                row_is_error = True
                                                success = False
                                        elif row[idx] != "":
                                            rowobject[row_num][columnname] = {
                                                "value": row[idx],
                                                "success": "False",
                                                "message": "expected Decimal value",
                                                "expected": "Decimal"
                                            }
                                            errorobject[error_row_num][columnname] = {
                                                "row": row_num,
                                                "value": row[idx],
                                                "success": "False",
                                                "message": "expected Decimal value",
                                                "expected": "Decimal"
                                            }
                                            column_messages[key][columnname] = "expected Decimal value but found something else"
                                            first_failure = False
                                            row_is_error = True
                                            success = False
                                    elif columntype == "yesorno":
                                        if not key in column_messages:
                                            column_messages[key] = {}
                                        if not columnname in column_messages[key]:
                                            column_messages[key][columnname] = ""

                                        if (
                                            row[idx] is not None
                                            and row[idx] != ""
                                            and bool_converter(row[idx]) == True
                                        ):
                                            b_value = True
                                            a_lower = row[idx].lower()
                                            if a_lower in ("true", "t", "y", "yes"):
                                                b_value = True
                                            if a_lower in ("false", "f", "n", "no"):
                                                b_value = False
                                            rowobject[row_num][columnname] = {
                                                "value": b_value,
                                                "success": "True",
                                                "message": "",
                                                "expected": ""
                                            }
                                            errorobject[error_row_num][columnname] = {
                                                "row": row_num,
                                                "value": b_value,
                                                "success": "True",
                                                "message": "",
                                                "expected": ""
                                            }
                                            success = True
                                        elif row[idx] != "":
                                            rowobject[row_num][columnname] = {
                                                "value": row[idx],
                                                "success": "False",
                                                "message": "expected True, False, yes, no  value",
                                                "expected": "Boolean (True, False, yes, no)"
                                            }
                                            errorobject[error_row_num][columnname] = {
                                                "row": row_num,
                                                "value": row[idx],
                                                "success": "False",
                                                "message": "expected True, False, yes, no  value",
                                                "expected": "Boolean (True, False, yes, no)"
                                            }
                                            column_messages[key][columnname] = "expected True, False, yes, no value but found something else"
                                            first_failure = False
                                            row_is_error = True
                                            success = False
                                    elif columntype == "character":
                                        if not key in column_messages:
                                            column_messages[key] = {}
                                        if not columnname in column_messages[key]:
                                            column_messages[key][columnname] = ""

                                        if row[idx] is not None and row[idx] != "":
                                            try:
                                                isinstance(row[idx], str)
                                                if (
                                                    columnname in charectercount
                                                    and key == "clinical_information"
                                                    and columnname != "sample_id"
                                                ):
                                                    newset = charectercount[columnname]
                                                    newset.add(
                                                        str_converter(row[idx]))
                                                    charectercount[columnname] = newset
                                                    if len(charectercount[columnname]) > 5:
                                                        charectercountcolumns.add(
                                                            columnname
                                                        )
                                                        message = "More than 5 categories in column"
                                                elif key == "clinical_information":
                                                    charectercount[columnname] = set(
                                                        [])
                                                rowobject[row_num][columnname] = {
                                                    "value": str_converter(row[idx]),
                                                    "success": "True",
                                                    "message": "",
                                                    "expected": ""
                                                }
                                                errorobject[error_row_num][columnname] = {
                                                    "row": row_num,
                                                    "value": str_converter(row[idx]),
                                                    "success": "True",
                                                    "message": "",
                                                    "expected": ""
                                                }
                                                success = True
                                                if columnname == "sample_id":
                                                    if row[idx] not in sample_ids[key]:
                                                        sample_ids[key].append(
                                                            row[idx])

                                            except BaseException:
                                                rowobject[row_num][columnname] = {
                                                    "value": row[idx],
                                                    "success": "False",
                                                    "message": "expected Text value",
                                                    "expected": "Character"
                                                }
                                                errorobject[error_row_num][columnname] = {
                                                    "row": row_num,
                                                    "value": row[idx],
                                                    "success": "False",
                                                    "message": "expected Text value",
                                                    "expected": "Character"
                                                }
                                                column_messages[key][columnname] = "expected Text value but found something else"
                                                first_failure = False
                                                row_is_error = True
                                                success = False
                                result[filename].append(rowobject)
                                row_num = row_num + 1
                                if row_is_error:
                                    error_rows[filename].append(errorobject)
                                    error_row_num = error_row_num + 1
                except FileNotFoundError as exception:
                    add_line_in_logger_file()
                    logger.exception(exception)
                    result[filename] = []
                    result[filename].append({filename: "file not found"})

                if len(charectercountcolumns) > 0 and key == "clinical_information":
                    result[filename] = []
                    result[filename].append(
                        {
                            filename: ",".join(charectercountcolumns)
                            + "columns has more than 15 same values"
                        }
                    )

            project_data = {}
            file_names = {}
            if first_failure:
                # Step 2 - Collecting unique sample Id's
                # we take all the sample id's from all the files and upload it to
                # unique_samples (unique)

                if is_clinical:
                    project_object.is_clinical=is_clinical
                    project_object.save()


                # if clin info exists, check if sample id of clin == sample id of others
                    unique_samples = [
                        sample
                        for key, value in sample_ids.items()
                        if key == "clinical_information"
                        for sample in value
                    ]
                    if len(unique_samples) > 0:
                        sample_check = True
                        for key, value in sample_ids.items():
                            if key != "clinical_information":
                                for sample_val in value:
                                    if sample_val not in unique_samples:
                                        sample_check = False
                                        break
                        if sample_check == False:
                            success = False
                            message = "SampleMismatch"
                            issue = "SampleMismatch"
                            # project_object.sql_path=db_path
                            project_object.viz_type=viz_type
                            project_object.project_status='error'
                            project_object.error_found=issue
                            project_object.is_clinical=is_clinical
                            project_object.save()

                else:
                # otherwise, take unique samples, form clin info table
                    unique_samples = set()
                    for lst in sample_ids.values():
                        unique_samples.update(lst)
                    unique_samples = list(unique_samples)
                    project_object.is_clinical=is_clinical

                    project_object.save()



                # Step 3 - saving the files and setting up the database

                if success == True:

                    user_project_directory = f"{settings.BASE_DIR}/media/{username}"
                    user_db_directory = os.path.join(
                        user_project_directory, "database")
                    if not os.path.exists(user_project_directory):
                        os.makedirs(user_project_directory)
                    if not os.path.exists(user_db_directory):
                        os.makedirs(user_db_directory)

                    db_path = os.path.join(user_db_directory, project_uuid)

                    create_hg38_shared_table(db_path)
                    create_master_phospho_table(db_path)


                    for key, value in result.items():
                        first_row = value[0]
                        tab = first_row["tab"]
                        file_names[tab] = key
                    tab_dependent_elements = [
                        "circos",
                        "heatmap",
                        "box",
                        "lollypop",
                        "sankey",
                    ]
                    available_visualizations = {}
                    uploaded_database_files = list(set(file_names.keys()))
                    file_exists = {
                        "cnv": "cnv" in uploaded_database_files,
                        "proteome": "proteome" in uploaded_database_files,
                        "clinical_information": "clinical_information" in uploaded_database_files,
                        "dna_mutation": "dna_mutation" in uploaded_database_files,
                        "methylation": "methylation" in uploaded_database_files,
                        "phospho": "phospho" in uploaded_database_files,
                        "rna": "rna" in uploaded_database_files,
                        "fusion": "fusion" in uploaded_database_files
                    }
                    for visualization, steps in visualization_tables_requirement.items():
                        if visualization in tab_dependent_elements:

                            ## inserting steps/tabs that only user uploaded, for heatmap if user uploaded
                            ## only phospho and rna, in available steps for heatmap only phospho and rna
                            ## will be inserted instead of all.

                            if any(step in uploaded_database_files for step in steps):
                                available_visualizations[visualization] = list(
                                    set(steps) & set(uploaded_database_files)
                                )
                        else:
                            if all(step in uploaded_database_files for step in steps):
                                available_visualizations[visualization] = list(
                                    steps)

                        if (
                            visualization == "survival"
                            and visualization in available_visualizations
                        ):
                            if "dna_mutation" in uploaded_database_files:
                                available_visualizations[visualization].append(
                                    "dna_mutation"
                                )
                            if "proteome" in uploaded_database_files:
                                available_visualizations[visualization].append(
                                    "proteome")
                            if "rna" in uploaded_database_files:
                                available_visualizations[visualization].append(
                                    "rna")


                    project_object = UserDataProjects.objects.get(project_id=project_uuid)
                    project_object.available_steps = available_visualizations
                    project_object.project_status = 'completed'
                    project_object.save()

                    project_id=project_object.project_id
                    # Step 4 - Creating the Rnid Tables and Data Base
                    create_and_get_rnids = create_rnid_table(
                        db_path, unique_samples)
                    if not is_clinical:
                        result["clinical_information"] = []
                        result["clinical_information"].append(
                            {
                                "columns": clinical_default_columns,
                                "tab": "clinical_information",
                            }
                        )

                    # Step 5 - Creating the Databases and required files
                    for key, value in result.items():

                        first_row = value[0]
                        tab = first_row["tab"]
                        filepath = f"{settings.BASE_DIR}/media/{username}/files/{key}"
                        if tab == 'dna_mutation':
                            if 'maf-merger' in maincolumns["file_types"]['dna_mutation']['filename']:
                                types_ = clinical_default_types
                            else:
                                types_ = (
                                    maincolumns["file_types"][tab]["types"]
                                    if is_clinical
                                    else clinical_default_types
                                )
                        else:
                            types_ = (
                                maincolumns["file_types"][tab]["types"]
                                if is_clinical
                                else clinical_default_types
                            )
                        create_db_and_tables1(
                            tab, db_path, types_, value, create_and_get_rnids, is_clinical
                        )
                        if tab == "rna":
                            full_path = f"{settings.BASE_DIR}/media/{username}/database/"
                            rna_res = create_volcano_csv_file(
                                full_path, filepath, project_id, tab
                            )
                            if rna_res == False:
                                continue
                        if tab == "proteome":
                            full_path = f"{settings.BASE_DIR}/media/{username}/database/"
                            proteome_res = create_volcano_csv_file(
                                full_path, filepath, project_id, tab
                            )
                            if proteome_res == False:
                                continue

                        if os.path.exists(filepath):
                            default_storage.delete(filepath)

                    if not is_clinical:
                        del result["clinical_information"]
                else:
                    file_exists={}
                    project_object.viz_type=viz_type
                    project_object.project_status='error'
                    project_object.error_found=issue
                    project_object.is_clinical=is_clinical
                    project_object.save()

            # Step 6 - If error exist we store the errors and send them in response

            if error_rows:
                data_issues = ""

                for errorfile in error_rows:
                    new_error_list = error_rows[errorfile].copy()
                    for _errors in error_rows[errorfile]:
                        if _errors.get("columns"):
                            new_error_list.remove(_errors)
                            if len(new_error_list) > 0:
                                _errors["is_error"] = True
                                result[errorfile] = error_rows[errorfile]
                                if data_issues == "":
                                    data_issues = "DataIssues"
                                break
                            else:
                                result[errorfile] = result[errorfile][:11]
                                break


            # step 7 - Deleting the files in the user directory
            user_files_directory = f"{settings.BASE_DIR}/media/{username}/files"
            delete_user_files(user_files_directory)

            response_data= {
                "result": result,
                "status": success,
                "issue": data_issues,
                "message": message,
                "project_details": project_data,
                "columnMessages": column_messages,
                "file_exists": file_exists,
                "project_id":project_uuid,
                # "project_status":'completed' if project_object.project_status!='error' else 'error',
                "project_status":project_object.project_status,
                # "project_name":project_name,
            }
            return Response(response_data)
        except (ObjectDoesNotExist, DatabaseError, IntegrityError, FileNotFoundError) as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")

@api_view(['GET'])
def check_project_status(request, project_id):
    try:
        # Fetch the project status
        project_status = UserDataProjects.objects.filter(project_id=project_id).first()
        if not project_status:
            return Response({'project_status': 'not_found'}, status=status.HTTP_404_NOT_FOUND)

        print(project_status.response)
        # Return the current status
        return Response({'project_status': project_status.project_status,'response':project_status.response}, status=status.HTTP_200_OK)

    except Exception as e:
        logger.exception(e)
        return Response({'error': 'An error occurred while checking project status'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class UploadFilesView(APIView):
    """
    API view for Uploading data.

    This view handles the uploading of single or multi data.

    Attributes:
        permission_classes (tuple): Tuple containing permission classes,
        requires user authentication.

    Methods:
        new_file_name(filename): Generate a random filename with the original file's extension.
        post(request): Handle the POST request for uploading files


    """
    def new_file_name(self, filename):
        """
        Generate a random filename with the original file's extension.

        Args:
            filename (str): Original filename.

        Returns:
            str: New random filename with the original file's extension.
        """
        _, file_extension = os.path.splitext(filename)
        chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890"
        randomstr = "".join((random.choice(chars)) for _ in range(10))
        return f"{randomstr}{file_extension}"

    # def post(self, request):
    def post(self, request, **args):

        project_id = uuid.uuid4()
        try:
            # username = self.request.user.username
            username = request.user.username if args else self.request.user.username
            project_name = request.data["project_name"]
            # project_name = project_name.replace(" ", "_")
            user_project_directory = f"{settings.BASE_DIR}/media/{username}"
            user_files_directory = os.path.join(user_project_directory, "files")
            # viz_type = "multi"
            viz_type = ""
            if args:
                viz_type = args["viz_type"]
            else:
                viz_type = 'multi'

            if not os.path.exists(user_project_directory):
                os.makedirs(user_project_directory)
            if not os.path.exists(user_files_directory):
                os.makedirs(user_files_directory)

            res = []
            if viz_type == 'multi':
                file_count = len(request.FILES)
                if 'mutation_file_name' in request.data:
                    file_count += 1
                if file_count < 2:
                    return Response(
                        {
                            "res": res,
                            "issue": "Please upload at least two files",
                            "project_name": project_name,
                            "status": 500,
                        }
                    )

            for user_file_object in request.FILES:
                tmp = {}
                file_data = request.FILES[user_file_object]
                file_name = file_data.name
                filepath = os.path.join(user_files_directory, file_name)
                default_storage.save(filepath, file_data)

                changed_name = self.new_file_name(file_data.name)
                changed_file_path = os.path.join(user_files_directory, changed_name)
                os.rename(filepath, changed_file_path)

                tmp["filename"] = changed_name
                tmp["filepath"] = changed_file_path
                tmp["tab"] = user_file_object
                res.append(tmp)


            user_db_directory = os.path.join(
                user_project_directory, "database")
            if not os.path.exists(user_project_directory):
                os.makedirs(user_project_directory)
            if not os.path.exists(user_db_directory):
                os.makedirs(user_db_directory)

            # uuid = uuid4.

            project_object = UserDataProjects(
                user=request.user if args else self.request.user,
                name=project_name,
                viz_type=viz_type,
                project_status='uploaded',
                project_id = project_id,
                sql_path= f"{user_project_directory}/database/{project_id}"
            )
            for file_info in res:
                tab_name = file_info["tab"]
                file_name = file_info["filename"]

                if hasattr(project_object, tab_name):  # Check if the tab matches a column
                    setattr(project_object, tab_name, file_name)

            project_object.save()  # Save the updated fields to the database
            last_id = project_object.pk
            # 4. Start the validation thread
            validate_thread = threading.Thread(target=self.validatefn, args=(request,res,project_object,viz_type))
            validate_thread.start()
            self.validatefn(request,res,project_object,viz_type)
            return Response({"res": res, "project_name": project_name, "project_status":"Uploaded","status": 200, "project_id":project_id })

        except Exception as e:
            logger.exception(e)
            project_object = UserDataProjects(
                user=request.user if args else self.request.user,
                name=project_name,
                viz_type=viz_type,
                project_status='failed',
                project_id=project_id,
                sql_path= f"{user_project_directory}/database/{project_id}"
            )
            for file_info in res:
                tab_name = file_info["tab"]
                file_name = file_info["filename"]

                if hasattr(project_object, tab_name):  # Check if the tab matches a column
                    setattr(project_object, tab_name, file_name)

            project_object.save()  # Save the updated fields to the database
            return HttpResponseServerError("An error occurred while uploading files.")

    def validatefn(self, request, res, project_object,viz_type):
        print('----came in validatefn')

        try:
            project_name = project_object.name
            project_uuid = project_object.project_id
            username = project_object.user
            user_project_directory = f"{settings.BASE_DIR}/media/{username}"
            user_files_directory = os.path.join(user_project_directory, "files")
            file_types = {}
            is_error = False
            viz_type='multi'

            resp=[]
            for item in res:
                tmp = item

                tab = item["tab"]
                filepath = item["filepath"]

                row_number = 0
                issue = "allFileColumns1"
                with open(filepath, "r") as file:
                    for each in file:
                        row = each.split("\t")
                        if row_number == 0:
                            length_of_columns = len(row)
                            columns = [e.strip() for e in row]
                            if (
                                tab == "clinical_information"
                            ) and length_of_columns <= 17:
                                column_validation = validate(
                                    columns, tab)
                                if column_validation["status"] == 200:
                                    tmp["columns"] = columns
                                    tmp["message"] = ""
                                    tmp["types"] = table_types[tab]
                                else:
                                    is_error = True
                                    tmp["columns"] = []
                                    tmp["message"] = column_validation["message"]
                                    tmp["types"] = table_types[tab]

                            elif tab == "clinical_information" and length_of_columns > 17:
                                is_error = True
                                tmp["columns"] = []
                                tmp["message"] = "Clinical Information File should have less\
                                    than or equal to 17 columns, more than 17 found"
                                issue = "allFileColumns2"

                            elif tab != "clinical_information":
                                column_validation = validate(
                                    columns, tab)
                                if column_validation["status"] == 200:
                                    tmp["columns"] = column_validation["finalcolumns"]
                                    tmp["message"] = ""
                                    tmp["types"] = table_types[tab]
                                else:
                                    is_error = True
                                    tmp["columns"] = []
                                    tmp["message"] = column_validation["message"]
                            else:
                                is_error = True
                                tmp["columns"] = []
                                tmp["message"] = "Error: Please Read Instructions"
                                issue = "allFileColumns3"
                            break

                resp.append(tmp)
            file_types = {}

            if not is_error:
                for item in resp:
                    tab = item["tab"]
                    filename = item["filename"]
                    types = {}
                    if tab != "clinical_information":
                        types = item["types"]
                    elif tab == "clinical_information":
                        types, errors, is_clinical_error = analyse_clinical_information(
                            item["filepath"]
                        )
                        if is_clinical_error:
                            delete_user_files(user_files_directory)
                            project_object.project_status = 'error'
                            project_object.error_found = errors
                            project_object.response = {
                                "res":res,
                                "issue":"clinicalInforamtionFile",
                                "clinicalRows":errors,
                                "project_name":project_name,
                                "status":200
                            }
                            project_object.save()

                        else:
                            project_object.project_status = 'no errors'
                            project_object.save()

                    if tab not in file_types:
                        file_types[tab] = {"tab": tab,
                                        "filename": filename, "types": types}
                    else:
                        file_types[tab]["filename"] = filename

            else:
                delete_user_files(user_files_directory)
                project_object.project_status = 'error'
                project_object.error_found = issue
                project_object.response = {
                    "res": res,
                    "issue": "allFileColumns",
                    "specific_issue":issue,
                    "project_name": project_name,
                    "status": 200,

                }
                project_object.save()

                return False
            # update in db - file verified

            username = self.request.user.username
            verify_view = VerifyClinicalDataColumns()

            #### Call the post method of VerifyClinicalDataColumns
            arguments = {"project_id": project_uuid}
            arguments["file_types"] = file_types
            arguments["viz_type"] = viz_type

            response = verify_view.post(
                request._request,
                **arguments,
            )
            if response:
                #because this function will not show any output on frontend any more... so we have to store the output in database only

                project_name = project_object.name
                response_data = response.data

                if response_data.get('project_status') =='completed':
                    # if response_data.get('message')=='' and response_data.get('issue')=='':
                    file_exists = response_data.get('file_exists')
                    if viz_type == 'multi':
                        ext_object = UserDataExtension(
                                    username=username,
                                    project_name=project_name,
                                    project_id=project_uuid,
                                    files=file_exists,
                                )
                        ext_object.save()
                    # return response_data
                    project_object.project_status='completed'
                    project_object.response = {
                        "res": response_data.get('result'),
                        "message": response_data.get('message'),
                        "issue": response_data.get('issue'),
                        "project_name": project_name,
                        "status": response_data.get('status'),
                    }
                    project_object.save()


        except (ObjectDoesNotExist, DatabaseError, IntegrityError, FileNotFoundError) as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")

#@method_decorator(csrf_exempt, name="dispatch")
class FilterJson(APIView):
    """
    API view for generating filter JSON for clinical data.

    This view handles the generation of filter JSON
    for clinical data stored in a project's database.
    It queries the database for relevant information
    about the clinical columns and prepares filter
    options for each column based on its data type.

    Methods:
        post(request): Handle the POST request for generating filter JSON.
    """

    def post(self, request):
        """
        Handle the POST request for generating filter JSON.

        This method queries the clinical data columns in a project's database,
        determines their data types, and generates filter options for each column.

        Args:
            request (HttpRequest): The HTTP request object containing project information.

        Returns:
            Response: A JSON response containing the generated filter options
            or an empty dictionary.
        """
        try:
            data = request.data
            project_id = data.get("project_id")

            if project_id is None:
                return Response(status=200)
            else:
                project_id = project_id.strip()

            project_information = UserDataProjects.objects.get(project_id=project_id)
            # logger.error(f'line 1441- proj id={project_information}')

            if project_information.is_clinical:
                result_json = {}
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

                    for res_value in res:
                        if res_value[1] != "pt_sbst_no" and res_value[1] != "id" and res_value[1] != "rnid":
                            if res_value[2] == "VARCHAR(155)":
                                jobs = {
                                    job[0]
                                    for job in cursor.execute(
                                        f"SELECT {res_value[1]} FROM clinical_information"
                                    )
                                }
                                result_json["Clinical Information"][res_value[1]] = []
                                for text in jobs:
                                    if text != "nan":
                                        result_json["Clinical Information"][res_value[1]].append(
                                            {
                                                "type": "checkbox",
                                                "name": res_value[1],
                                                "id": f"{res_value[1]}_{text}",
                                                "value": f"{text}",
                                            }
                                        )

                            elif res_value[2] == "FLOAT" or res_value[2] == "INT":
                                result_json["Clinical Information"][res_value[1]] = []
                                query1 = f"SELECT MIN({res_value[1]}), MAX({res_value[1]}) FROM clinical_information"
                                cursor1 = conn.execute(query1)
                                res1 = cursor1.fetchall()
                                min = 0
                                max = 0
                                if res1[0][0] is not None:
                                    min = res1[0][0]
                                if res1[0][1] is not None:
                                    max = res1[0][1]
                                result_json["Clinical Information"][res_value[1]].append(
                                    {
                                        "type": "number",
                                        "name": res_value[1],
                                        "id": res_value[1],
                                        "min": min,
                                        "max": max,
                                    }
                                )
                            elif res_value[2] == "BOOLEAN":
                                result_json["Clinical Information"][res_value[1]] = []
                                result_json["Clinical Information"][res_value[1]].append(
                                    {
                                        "type": "checkbox",
                                        "name": res_value[1],
                                        "id": f"{res_value[1]}_yes",
                                        "value": "yes",
                                    }
                                )
                                result_json["Clinical Information"][res_value[1]].append(
                                    {
                                        "type": "checkbox",
                                        "name": res_value[1],
                                        "id": f"{res_value[1]}_no",
                                        "value": "no",
                                    }
                                )
                    return Response({"filterJson": result_json, "status": 200})
                except Exception as e:
                    add_line_in_logger_file()
                    logger.exception(e)
                    return Response({"filterJson": {}, "status": 204})
            else:
                return Response({"filterJson": {}, "status": 200})
        except (ObjectDoesNotExist, DatabaseError, IntegrityError, FileNotFoundError) as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")

@method_decorator(csrf_protect, name="dispatch")
class KeysAndValuesFilterJson(APIView):
    """
    API view for generating filter JSON for clinical data.

    This view handles the generation of filter JSON for clinical data stored in a project's database.
    It queries the database for relevant information about the clinical columns and prepares filter
    options for each column based on its data type.

    Methods:
        post(request): Handle the POST request for generating filter JSON.
    """

    def post(self, request):
        """
        Handle the POST request for generating filter JSON.

        This method queries the clinical data columns in a project's database,
        determines their data types, and generates filter options for each column.

        Args:
            request (HttpRequest): The HTTP request object containing project information.

        Returns:
            Response: A JSON response containing the generated filter options
            or an empty dictionary.
        """

        try:
            data = request.data
            project_id = data.get("project_id")
            if project_id is None:
                return Response(status=204)
            else:
                project_id = project_id.strip()
            logger.info(f'project id in keysANDvalues= {project_id}')
            project_information = UserDataProjects.objects.get(project_id=project_id)
            result_json = {}
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

                result_json = {}
                result_json["column_type_json"] = {}
                for x_value in res:
                    if x_value[1] != "pt_sbst_no" and x_value[1] != "id" and x_value[1] != "rnid":
                        if x_value[2] == "VARCHAR(155)":
                            jobs = {
                                job[0]
                                for job in cursor.execute(
                                    f"SELECT {x_value[1]} FROM clinical_information"
                                )
                            }
                            for text in jobs:
                                key_ = f"{x_value[1]}_{text}"
                                if text != "nan":
                                    result_json[key_] = {
                                        "type": "checkbox",
                                        "name": x_value[1],
                                        "id": f"{x_value[1]}_{text}",
                                        "value": f"{text}",
                                    }

                        elif x_value[2] == "FLOAT" or x_value[2] == "INT":
                            query1 = f"SELECT MIN({x_value[1]}), MAX({x_value[1]}) FROM clinical_information"
                            cursor1 = conn.execute(query1)
                            res1 = cursor1.fetchall()
                            min = 0
                            max = 0
                            key1 = f"from_{x_value[1]}"
                            key2 = f"to_{x_value[1]}"
                            if res1[0][0] is not None:
                                min = res1[0][0]
                            if res1[0][1] is not None:
                                max = res1[0][1]

                            result_json[key1] = {
                                "type": "number",
                                "name": x_value[1],
                                "id": key1,
                                "min": min,
                                "max": max,
                            }

                            result_json[key2] = {
                                "type": "number",
                                "name": x_value[1],
                                "id": key2,
                                "min": min,
                                "max": max,
                            }
                            result_json["column_type_json"][x_value[1]] = "number"

                        elif x_value[2] == "BOOLEAN":
                            key1 = f"{x_value[1]}_yes"
                            key2 = f"{x_value[1]}_no"
                            result_json[key1] = {
                                "type": "checkbox",
                                "name": x_value[1],
                                "id": key1,
                                "value": "yes",
                            }
                            result_json[key2] = {
                                "type": "checkbox",
                                "name": x_value[1],
                                "id": key2,
                                "value": "no",
                            }
                            result_json["column_type_json"][x_value[1]] = "boolean"
            except Exception as exception:
                add_line_in_logger_file()
                logger.exception(exception)
            return Response(result_json, status=status.HTTP_200_OK)
        except (ObjectDoesNotExist, DatabaseError, IntegrityError, FileNotFoundError) as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")


@method_decorator(csrf_protect, name="dispatch")
class UserDataVisualizationProjects(APIView):
    """
    API view for retrieving user's visualization project data.

    This view allows users to retrieve information about their visualization projects.
    Users can retrieve all their projects or fetch details about a specific project.

    Attributes:
        permission_classes (tuple): Tuple containing permission classes to control access.
            In this case, only authenticated users are allowed.

    Methods:
        get(request, project_id=None): Handle the GET request for retrieving project data.
    """
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request, project_id=None):
        """
        Handle the GET request for retrieving project data.

        Args:
            request (HttpRequest): The HTTP request object.
            project_id (int, optional): The ID of the specific project to retrieve.
            Defaults to None.

        Returns:
            Response: A JSON response containing project data
            or an error message with a status code.
        """
        try:
            user = request.user
            if project_id is None:
                table_data = UserDataProjects.objects.filter(
                    user=user).order_by("-id")
                serializer = UserDataProjectsGetSerializer(
                    table_data, many=True)
            elif project_id:
                table_data = UserDataProjects.objects.get(user=user, project_id=project_id)
                serializer = UserDataProjectsGetSerializer(table_data)

            return Response(serializer.data, status=200)

        except (ObjectDoesNotExist, DatabaseError, IntegrityError, FileNotFoundError) as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")


@method_decorator(csrf_protect, name="dispatch")
class UserDataExtensionProjectsDetails(APIView):
    """
    API view for retrieving details of user's visualization projects.

    This view allows users to retrieve details of their visualization projects.
    Users can filter projects based on title, content, or writer,
    and can also paginate the results.

    Attributes:
        permission_classes (tuple): Tuple containing permission classes to control access.
        In this case, only authenticated users are allowed.

    Methods:
        get(request): Handle the GET request for retrieving project details.
        post(request): Handle the POST request for filtering and retrieving project details.
    """
    permission_classes = (permissions.IsAuthenticated,)
    def get(self, request):
        """
        Handle the GET request for retrieving project details.

        Args:
            request (HttpRequest): The HTTP request object.

        Returns:
            Response: A JSON response containing project details or an empty response.
        """
        user = request.user
        username = request.user.username
        project_type = request.GET.get('project_type', 'active')  # 'active' or 'deleted'
        project_ids = UserDataProjects.objects.filter(
            viz_type='multi').values_list('project_id', flat=True)
        current_time = now()

        if project_type == 'active':
            projects_data = UserDataExtension.objects.filter(
                username=username,
                deleted_on__isnull=True,
                project_id__in=project_ids
            ).order_by("-id")
        else:
            projects_data = UserDataExtension.objects.filter(
                username=username,
                deleted_on__isnull=False
            ).order_by("-id")
        per_page = int(request.GET.get('per_page', 2))
        page_number = int(request.GET.get('page', 1))

        paginator = Paginator(projects_data, per_page)
        page_obj = paginator.get_page(page_number)
        serializer = UserDataExtensionSerializer(page_obj, many=True)

        if serializer.data:
            return Response(
                {
                    "data": serializer.data,
                    "total": page_obj.paginator.count,
                    "page": int(page_number),
                    "total_pages": paginator.num_pages
                },
                status=200,
            )
        return Response(status=200)


    def post(self, request):
        """
        Handle the POST request for filtering and retrieving project details.

        Args:
            request (HttpRequest): The HTTP request object.

        Returns:
            Response: A JSON response containing filtered project details or an empty response.
        """
        user = request.user
        username = request.user.username
        type = request.data.get("type")
        search = request.data.get("searchTerm")
        projects_data_obj = ProjectDataSerializer.objects.get(
            user=user, viz_type="multi"
        )
        if type == "title":
            projects_data = projects_data_obj.filter(title__icontains=search).order_by(
                "-id"
            )
        elif type == "content":
            projects_data = projects_data_obj.filter(
                content__icontains=search
            ).order_by("-id")
        elif type == "writer":
            projects_data = projects_data_obj.filter(writer__icontains=search).order_by(
                "-id"
            )

        per_page = int(request.GET.get('per_page', 10))
        page_number = int(request.GET.get('page', 1))

        paginator = Paginator(projects_data, per_page)
        page_obj = paginator.get_page(page_number)
        serializer = ProjectDataSerializer(page_obj, many=True)
        if serializer.data:
            return Response(
                {
                    "data": serializer.data,
                    "total": page_obj.paginator.count,
                    "current_page": page_number,
                    "total_pages": paginator.num_pages
                },
                status=200
            )
        return Response(status=204)

@method_decorator(csrf_protect, name="dispatch")
class UserDataVisualizationProjectsCount(APIView):
    """
    API view for retrieving the count of user's visualization projects.

    This view allows users to retrieve the count of their visualization projects.

    Attributes:
        permission_classes (tuple): Tuple containing permission classes to control access.
            In this case, only authenticated users are allowed.

    Methods:
        get(request): Handle the GET request for retrieving the count of projects.
    """
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request):

        """
        Handle the GET request for retrieving the count of projects.

        Args:
            request (HttpRequest): The HTTP request object.

        Returns:
            Response: A JSON response containing the count of projects or an empty response.
        """
        user = request.user
        try:
            projects_data = (
                UserDataProjects.objects.all()
                .filter(user=user, viz_type="multi")
                .order_by("-id")
            )
            filtered_projects_data = []

            for project in projects_data:
                if project.sql_path:
                    try:
                        if not os.path.exists(project.sql_path):
                            continue
                        filtered_projects_data.append(project)
                    except FileNotFoundError:
                        continue
            count = len(filtered_projects_data)
        except ObjectDoesNotExist:
            return Response(status=204)
        except (DatabaseError, IntegrityError, SuspiciousFileOperation) as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")

        return Response({"data": count}, status=200)


@method_decorator(csrf_protect, name="dispatch")
class UserDataExtensionProjectsCount(APIView):
    """
    API view for retrieving the count of user's visualization projects.

    This view allows users to retrieve the count of their visualization projects.

    Attributes:
        permission_classes (tuple): Tuple containing permission classes to control access.
            In this case, only authenticated users are allowed.

    Methods:
        get(request): Handle the GET request for retrieving the count of projects.
    """
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request):

        """
        Handle the GET request for retrieving the count of projects.

        Args:
            request (HttpRequest): The HTTP request object.

        Returns:
            Response: A JSON response containing the count of projects or an empty response.
        """
        user = request.user
        username = request.user.username
        try:
            projects_data = (
                UserDataExtension.objects.all()
                .filter(username=username)
                .order_by("-id")
            )
            count = len(projects_data)
        except ObjectDoesNotExist:
            return Response(status=204)
        except (DatabaseError, IntegrityError, SuspiciousFileOperation) as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")

        return Response({"data": count}, status=200)

@method_decorator(csrf_protect, name="dispatch")
class UserProjectFilesDataTable(APIView):
    """
    API view for retrieving a sample of data from user project database tables.

    This view allows users to retrieve a sample of data from various database tables
    associated with a specific project.

    Methods:
        post(request): Handle the POST request for retrieving data samples.
    """

    def post(self, request):
        """
        Handle the POST request for retrieving data samples.

        Args:
            request (HttpRequest): The HTTP request object.

        Returns:
            Response: A JSON response containing samples of data from database tables
            or an empty response.
        """
        data = request.data
        project_id = data.get("project_id")
        if project_id is None:
            return Response(status=204)
        project_id = int(project_id)
        try:
            project_information = UserDataProjects.objects.get(project_id=project_id)
            database_path = project_information.sql_path
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
            create_database = [
                "dna_mutation",
                "methylation",
                "rna",
                "proteome",
                "clinical_information",
                "fusion",
                "cnv",
                "phospho",
            ]
            table_dict = {}
            for table_name in create_database:
                try:
                    column_names_of_table = list(globals()[table_name].keys())

                    keys_str = ",".join(column_names_of_table)
                    query = f"select 1 as id, {keys_str} from {table_name} limit 50"
                    query_response_object = ClinicalInformation.objects.using(
                        "userdata"
                    ).raw(query)
                    response = []

                    for row in query_response_object:
                        all_fields_in_a_row = {}
                        for column_name in column_names_of_table:
                            column_name = column_name.strip()
                            try:
                                all_fields_in_a_row[column_name] = getattr(
                                    row, column_name
                                )
                            except ObjectDoesNotExist:
                                return Response(status=204)
                            except (DatabaseError, IntegrityError, SuspiciousFileOperation) as e:
                                add_line_in_logger_file()
                                logger.exception(e)
                                return HttpResponseServerError("An error occurred while processing your request.")
                            except Exception as e:
                                add_line_in_logger_file()
                                logger.exception(e)
                                return HttpResponseServerError("An error occurred while processing your request.")
                        response.append(all_fields_in_a_row)

                    table_dict[table_name] = response
                except ObjectDoesNotExist:
                    return Response(status=204)
                except (DatabaseError, IntegrityError, SuspiciousFileOperation) as e:
                    add_line_in_logger_file()
                    logger.exception(e)
                    return HttpResponseServerError("An error occurred while processing your request.")
                except Exception as e:
                    add_line_in_logger_file()
                    logger.exception(e)
                    return HttpResponseServerError("An error occurred while processing your request.")
            return Response(table_dict, status=200)
        except ObjectDoesNotExist:
            return Response(status=204)
        except (DatabaseError, IntegrityError, SuspiciousFileOperation) as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")


class CreateSharedDB(APIView):
    """
    A view to create a shared SQLite database from a CSV file.

    This view is designed to create a shared SQLite database using data from
    a CSV file. The CSV file is read into a DataFrame, and its contents are
    stored in a database table. The database file is created within the user's
    project directory in the 'database' subdirectory.

    Note: This view assumes that the CSV file 'hg38.csv' is located in the
    'static/db_files' directory.

    Methods:
        get: Handle GET requests to create the shared database.

    Attributes:
        None

    Example:
        To create the shared database, make a GET request to this view.

    Returns:
        Response: A response indicating the success status of the database creation.
    """

    def get(self, request):
        try:
            user_project_directory = f"{settings.BASE_DIR}/media/"
            user_db_directory = os.path.join(user_project_directory, "database")
            if not os.path.exists(user_project_directory):
                os.makedirs(user_project_directory)
            if not os.path.exists(user_db_directory):
                os.makedirs(user_db_directory)

            db_name = "shared_hg38"
            file_name = "static/db_files/hg38.csv"
            db_name_ = "Mphospho"

            db_path = os.path.join(user_db_directory, db_name)
            conn = sql.connect(db_path)
            df1 = pd.read_csv(file_name, sep=",")
            df1.to_sql(db_name_, conn, if_exists="replace", index_label="id")
            conn.close()
            return Response({"success": {}, "status": 200})
        except IntegrityError as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("A database integrity constraint violation occurred.")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")


class DeleteDirectoryContentsAPIView(APIView):
    """
    A view to delete the contents of a directory.

    This view provides functionality to delete the contents of a specified directory.
    It is designed to remove all files within the specified directory, leaving the
    directory itself intact.

    Methods:
        get: Handle GET requests to delete the contents of the directory.

    Attributes:
        None

    Example:
        To delete the contents of the directory, make a GET request to this view.

    Returns:
        Response: A response indicating the status of the directory contents deletion.
    """

    def get(self, request):
        database_directory_path = f"{settings.BASE_DIR}/media/sohel/database"
        files_directory_path = f"{settings.BASE_DIR}/media/sohel/files"
        try:
            # Delete the contents inside the directory
            for filename in os.listdir(files_directory_path):
                file_path = os.path.join(files_directory_path, filename)
                if os.path.isfile(file_path):
                    os.remove(file_path)

            for filename in os.listdir(database_directory_path):
                file_path = os.path.join(database_directory_path, filename)
                if os.path.isfile(file_path):
                    os.remove(file_path)

            return Response({"message": "Directory contents deleted successfully"})
        except OSError as exception:
            return Response(
                {"message": f"Error deleting directory contents: {str(exception)}"}, status=500
            )
        except IntegrityError as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("Integrity error: A database integrity constraint violation occurred.")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")

@method_decorator(csrf_protect, name="dispatch")
class UserDataVisualizationProjectsDelete(APIView):
    """
    API view for retrieving user's visualization project data.

    This view allows users to retrieve information about their visualization projects.
    Users can retrieve all their projects or fetch details about a specific project.

    Attributes:
        permission_classes (tuple): Tuple containing permission classes to control access.
            In this case, only authenticated users are allowed.

    Methods:
        get(request, project_id=None): Handle the GET request for retrieving project data.
    """
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request, project_id=None):
        """
        Handle the GET request for retrieving project data.

        Args:
            request (HttpRequest): The HTTP request object.
            project_id (int, optional): The ID of the specific project to retrieve.
            Defaults to None.

        Returns:
            Response: A JSON response containing project data
            or an error message with a status code.
        """
        try:
            user = request.user
            username = request.user.username
            if project_id:
                table_data = UserDataProjects.objects.get(
                    user=user, project_id=project_id)
                if table_data.sql_path:
                    try:
                        if os.path.exists(table_data.sql_path):
                            os.remove(table_data.sql_path)

                        proteome_path = f"{settings.BASE_DIR}/media/{username}/database/{project_id}_proteome.csv"
                        transcriptome_path = f"{settings.BASE_DIR}/media/{username}/database/{project_id}_transcriptome.csv"

                        if os.path.exists(proteome_path):
                            os.remove(proteome_path)

                        if os.path.exists(transcriptome_path):
                            os.remove(transcriptome_path)

                        UserDataExtension.objects.filter(
                            username=username, project_id=project_id).update(
                            deleted_on=datetime.now()
                        )
                    except ObjectDoesNotExist as e:
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError("File Not Found.")
                    except (DatabaseError, IntegrityError, SuspiciousFileOperation) as e:
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError("An error occurred while processing your request.")
                    except Exception as e:
                        add_line_in_logger_file()
                        logger.exception(e)
                        return HttpResponseServerError("An error occurred while processing your request.")

                table_data.delete()
            return Response({"message": "File deleted Successfully"}, status=200)
        except ObjectDoesNotExist as e:
            return HttpResponseServerError("An error occurred while processing your request.")
        except (DatabaseError, IntegrityError, SuspiciousFileOperation) as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")
        except Exception as e:
            add_line_in_logger_file()
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")

@method_decorator(csrf_exempt, name="dispatch")
class UserDataProjectsExtend(APIView):
    """
    API view for extending user's visualization project.

    This view allows users to extend their visualization projects by updating the
    uploaded_date and recording the extension in UserDataExtension table.

    Attributes:
        permission_classes (tuple): Tuple containing permission classes to control access.
            In this case, only authenticated users are allowed.

    Methods:
        post(request, project_id=None): Handle the POST request for extending the project.
    """
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request, project_id=None):
        """
        Handle the POST request for extending project data.

        Args:
            request (HttpRequest): The HTTP request object.
            project_id (int, optional): The ID of the specific project to extend. Defaults to None.

        Returns:
            Response: A JSON response confirming the extension or an error message with a status code.
        """
        try:
            user = request.user
            username = request.user.username
            reason = request.data.get("reason")
            if project_id:
                try:
                    # project = UserDataProjects.objects.get(user=user, id=project_id)

                    # project.uploaded_date = datetime.now()
                    # project.save()

                    UserDataExtension.objects.filter(
                        username=username, project_id=project_id).update(
                        # extended_on=project.uploaded_date,
                        extended_on=datetime.now(),
                        reason_for_extension=reason
                    )

                    return Response({"message": "Project extended successfully"}, status=200)
                except ObjectDoesNotExist:
                    return Response({"error": "Project not found."}, status=404)
                except (DatabaseError, IntegrityError) as e:
                    logger.exception(e)
                    return HttpResponseServerError("An error occurred while processing your request.")
                except Exception as e:
                    logger.exception(e)
                    return HttpResponseServerError("An error occurred while processing your request.")
            else:
                return Response({"error": "Project ID is required."}, status=400)
        except Exception as e:
            logger.exception(e)
            return HttpResponseServerError("An error occurred while processing your request.")

class DeleteExpiredProjects(APIView):

    def delete_files(self, sql_path, username, project_id):
        # Only try to delete sql_path if it exists and is not None
        if sql_path and os.path.exists(sql_path):
            os.remove(sql_path)

        proteome_path = os.path.join(
            settings.BASE_DIR, f"media/{username}/database/{project_id}_proteome.csv")
        transcriptome_path = os.path.join(
            settings.BASE_DIR, f"media/{username}/database/{project_id}_transcriptome.csv")

        for path in [proteome_path, transcriptome_path]:
            if os.path.exists(path):
                os.remove(path)

    # def delete_projects(self, projects_to_delete):
    #     for project_data in projects_to_delete:
    #         try:
    #             self.delete_files(
    #                 project_data.sql_path, project_data.user.username, project_data.project_id
    #             )
    #         except Exception as e:
    #             logger.exception(e)
    #             return False

    #     # Convert the queryset to a list before bulk deleting
    #     projects_to_delete_list = list(projects_to_delete)

    #     # Bulk delete the projects
    #     # UserDataExtension.objects.filter(
    #     #     project_id__in=[project.id for project in projects_to_delete_list]
    #     #     ).update(deleted_on=datetime.now())
    #     UserDataExtension.objects.filter(
    #         project_id__in=[project.id for project in projects_to_delete_list]
    #     ).update(deleted_on=now())
    #     UserDataProjects.objects.filter(
    #         project_id__in=[project.project_id for project in projects_to_delete_list]
    #         ).delete()
    def delete_projects(self, projects_to_delete):
        """Delete projects and their associated data."""
        for project_data in projects_to_delete:
            try:
                self.delete_files(
                    project_data.sql_path, project_data.user.username, project_data.project_id)
            except Exception as e:
                logger.exception(e)

        # Update `deleted_on` timestamp
        UserDataExtension.objects.filter(
            project_id__in=[project.project_id for project in projects_to_delete]
        ).update(deleted_on=timezone.now())
        # Bulk delete projects
        UserDataProjects.objects.filter(
            project_id__in=[project.project_id for project in projects_to_delete]
        ).delete()

    def delete_unwanted_files(self):
        media_path = os.path.join(settings.BASE_DIR, "media/")
        if os.path.exists(media_path):
            for item in os.listdir(media_path):
                item_path = os.path.join(media_path, item)
                if os.path.isfile(item_path):  # Check if it's a file
                    os.remove(item_path)  # Delete the file
        else:
            add_line_in_logger_file()
            logger.error("The 'Media' directory does not exist.")

    def delete_directory_contents(self,directory_path, directory_name):
        if os.path.exists(directory_path):
            for item in os.listdir(directory_path):
                item_path = os.path.join(directory_path, item)
                if os.path.isdir(item_path):
                    shutil.rmtree(item_path)
                else:
                    os.remove(item_path)
        else:
            add_line_in_logger_file()
            logger.error(f"The '{directory_name}' directory does not exist.")

    def delete_tool_files(self):
        self.delete_directory_contents(
            os.path.join(settings.BASE_DIR, "media/Blast/inputfiles"),
            "Blast Inputfiles"
            )
        self.delete_directory_contents(
            os.path.join(settings.BASE_DIR, "media/Blast/outputfiles"),
            "Blast Outputfiles"
            )

        self.delete_directory_contents(
            os.path.join(settings.BASE_DIR, "media/VcfMaf"),
            "VCFMAF"
            )
        self.delete_directory_contents(
            os.path.join(settings.BASE_DIR, "media/Interpro"),
            "Interpro"
            )
        self.delete_directory_contents(
            os.path.join(settings.BASE_DIR, "media/MAFMerger"),
            "MAFMerger"
            )

        self.delete_directory_contents(
            os.path.join(settings.BASE_DIR, "media/RefVerConverter/input"),
            "RefVer Inputfiles"
            )
        self.delete_directory_contents(
            os.path.join(settings.BASE_DIR,
                         "media/RefVerConverter/output"),
            "RefVer Outputfiles"
            )

    # def delete_expired_projects_deactivate_users(self):
    #     try:
    #         self.delete_tool_files()
    #         self.delete_unwanted_files()  # For volcano Files

    #         # Assuming uploaded_date is in UTC
    #         threshold_datetime = timezone.now() - timezone.timedelta(days=14)

    #         data_projects_to_delete = UserDataProjects.objects.filter(
    #             uploaded_date__lt=threshold_datetime)

    #         data_extension_to_delete = UserDataExtension.objects.filter(
    #             uploaded_date__lt=threshold_datetime)

    #         # Adjust threshold for extended projects in UserDataExtension
    #         for project in data_extension_to_delete:
    #             if project.extended_on:
    #                 extended_threshold = project.uploaded_date + timezone.timedelta(days=28)
    #                 if project.uploaded_date >= extended_threshold:
    #                     data_extension_to_delete = data_extension_to_delete.exclude(project_id=project.project_id)

    #         # Adjust threshold for extended projects in UserDataProjects
    #         for project in data_projects_to_delete:
    #             extension = UserDataExtension.objects.filter(project_id=project.project_id).first()
    #             if extension and extension.extended_on:
    #                 extended_threshold = extension.uploaded_date + timezone.timedelta(days=28)
    #                 if project.uploaded_date >= extended_threshold:
    #                     data_projects_to_delete = data_projects_to_delete.exclude(project_id=project.project_id)

    #         self.delete_projects(data_projects_to_delete)
    #         self.delete_projects(data_extension_to_delete)

    #         add_line_in_logger_file()
    #         logger.error("Successfully Deleted")

    #     except Exception as e:
    #         add_line_in_logger_file()
    #         logger.exception(e)
    #         return Response({"status": "Databases could not be deleted"}, status=200)
    def delete_expired_projects_deactivate_users(self):
        """Main API to delete expired projects."""
        try:
            self.delete_tool_files()

            # Define expiry thresholds
            default_expiry = timezone.now() - timezone.timedelta(days=14)
            extended_expiry = timezone.now() - timezone.timedelta(days=28)

            # Identify expired UserDataExtension projects
            data_extension_to_delete = UserDataExtension.objects.filter(
                Q(extended_on__isnull=True, uploaded_date__lt=default_expiry) |  # Not extended
                Q(extended_on__isnull=False, uploaded_date__lt=extended_expiry)  # Extended
            )

            # Identify expired UserDataProjects based on extensions
            data_projects_to_delete = UserDataProjects.objects.filter(
                Q(project_id__in=data_extension_to_delete.values_list('project_id', flat=True)) |
                Q(uploaded_date__lt=default_expiry)
            )

            # Delete projects
            self.delete_projects(data_extension_to_delete)
            self.delete_projects(data_projects_to_delete)

            logger.info("Successfully Deleted Expired Projects")
            return Response({"status": "Successfully Deleted Expired Projects"}, status=200)
        except Exception as e:
            logger.exception(e)
            return Response({"status": "Failed to Delete Expired Projects"}, status=500)

def table_converters(types, data_frame):
    """
    Convert columns of a DataFrame to specified data types.

    This function takes a dictionary of column names and their corresponding data types,
    and a DataFrame. It then performs type conversions on the DataFrame columns based on
    the specified data types.

    Args:
        types (dict): A dictionary containing column names as keys and their corresponding
                      data types ("character", "numeric", "decimal", "yesorno") as values.
        data_frame (pandas.DataFrame): The DataFrame containing the data to be converted.

    Returns:
        pandas.DataFrame: The DataFrame with columns converted to specified data types.
    """
    for key, value in types.items():
        if value == "character":
            if key == "sample_id":
                data_frame["pt_sbst_no"] = data_frame["pt_sbst_no"].astype(
                    str, errors="ignore")
            else:
                data_frame[key] = data_frame[key].astype(str)
        elif value == "numeric":
            data_frame[key] = data_frame[key].astype(int, errors="ignore")
        elif value == "decimal":
            data_frame[key] = data_frame[key].astype(float, errors="ignore")
        elif value == "yesorno":
            data_frame[key] = data_frame[key].astype(bool, errors="ignore")

    return data_frame


def create_clinical_table(table_types):
    """
    Create a SQL schema for a clinical information table.

    This function takes a dictionary of column names and their corresponding data types,
    and generates a SQL schema for a clinical information table based on the specified
    data types.

    Args:
        table_types (dict): A dictionary containing column names as keys and their
                            corresponding data types ("character", "numeric", "decimal",
                            "yesorno") as values.

    Returns:
        str: A SQL schema string for creating a clinical information table with the
             specified columns and data types.
    """
    d_list = []
    for key, value in table_types.items():
        if value == "character":
            if key == "sample_id":
                d_list.append("pt_sbst_no VARCHAR(155)")
            else:
                d_list.append(f"{key} VARCHAR(155)")
        elif value == "numeric":
            d_list.append(f"{key} INT")
        elif value == "decimal":
            d_list.append(f"{key} FLOAT")
        elif value == "yesorno":
            d_list.append(f"{key} BOOLEAN")
    schema = f" CREATE TABLE IF NOT EXISTS clinical_information ({' , '.join(d_list)},id INT PRIMARY KEY, rnid INT)"
    return schema


def create_db_and_tables1(type_, db_path, table_types, table_data, rnids, is_clinical):
    """
    Create a database and tables based on the provided data.

    This function creates a database connection using the given database path and
    creates tables based on the specified type, table types, table data, RNIDs,
    and whether the data is clinical or not.

    Args:
        type_ (str): The type of table to be created (e.g., "clinical_information", "proteome").
        db_path (str): The path to the database.
        table_types (dict): A dictionary containing column names as keys and their
                            corresponding data types ("character", "numeric", "decimal",
                            "yesorno") as values.
        table_data (list): A list of dictionaries containing table data.
        rnids (dict): A dictionary containing sample IDs as keys and RNIDs as values.
        is_clinical (bool): Indicates whether the data is clinical or not.

    Returns:
        None
    """
    # type_ = tab like clinincal, phospho etc.
    conn = sql.connect(db_path)

    conn.execute(f"DROP TABLE IF EXISTS {type_}")

    if type_ == "clinical_information":
        schema = create_clinical_table(table_types)
    else:
        schema = create_database[type_]

    sample_id_tables = [
        "clinical_information",
        "methylation",
        "rna",
        "proteome",
        "phospho",
        "fusion",
        "cnv",
    ]
    conn.execute(schema)
    if len(table_data) > 1000:
        total = len(table_data)
        z_start_index = 1
        kindex = 500
        j_value = 1
        while j_value < total:
            rows = []
            for index in range(z_start_index, kindex):
                row = {}
                if j_value < total:
                    for key, value in table_data[j_value].items():
                        for key_inner, value_inner in value.items():
                            if key_inner == "sample_id" and type_ in sample_id_tables:
                                row["pt_sbst_no"] = value_inner["value"]
                                row["rnid"] = rnids[value_inner["value"]]
                            elif key_inner == "sample_id" and type_ == "dna_mutation":
                                row["tumor_sample_barcode"] = value_inner["value"]
                                row["rnid"] = rnids[value_inner["value"]]
                            elif key_inner == "gene_name" and type_ == "dna_mutation":
                                row["hugo_symbol"] = value_inner["value"]
                            else:
                                row[key_inner] = value_inner["value"]
                        j_value += 1
                    rows.append(row)

            data_frame = pd.DataFrame(rows)
            if type_ == "clinical_information":
                data_frame = table_converters(table_types, data_frame)

            if type_ == "rna":
                data_frame.rename(columns={"raw": "gene_vl", "norm": "z_score"}, inplace=True)

            length_df = len(rows)
            data_frame.index = pd.RangeIndex(start=z_start_index, stop=z_start_index + length_df, step=1)
            data_frame.to_sql(type_, conn, if_exists="append", index=True, index_label="id")
            kindex += 500
            z_start_index += 500
    else:
        rows = []
        if not is_clinical and type_ == "clinical_information":
            for key, value in rnids.items():
                row = {}
                row["pt_sbst_no"] = key
                row["rnid"] = value
                row["rlps_yn"] = None
                row["rlps_cnfr_drtn"] = None
                row["death_yn"] = None
                row["death_cnfr_drtn"] = None

                rows.append(row)
        else:
            for index in range(1, len(table_data)):
                row = {}
                for key, value in table_data[index].items():
                    for key_inner, value_inner in value.items():
                        if key_inner == "sample_id" and type_ in sample_id_tables:
                            row["pt_sbst_no"] = value_inner["value"]
                            row["rnid"] = rnids[value_inner["value"]]
                        elif key_inner == "sample_id" and type_ == "dna_mutation":
                            row["tumor_sample_barcode"] = value_inner["value"]
                            row["rnid"] = rnids[value_inner["value"]]
                        elif key_inner == "gene_name" and type_ == "dna_mutation":
                            row["hugo_symbol"] = value_inner["value"]
                        else:
                            row[key_inner] = value_inner["value"]
                rows.append(row)
        data_frame = pd.DataFrame(rows)
        if type_ == "clinical_information":
            data_frame = table_converters(table_types, data_frame)

        if type_ == "rna":
            data_frame.rename(columns={"raw": "gene_vl", "norm": "z_score"}, inplace=True)
        data_frame.to_sql(type_, conn, if_exists="append", index=True, index_label="id")
    if type_ == "rna":
        conn.execute("DROP VIEW if exists transcriptomevolcano")
        conn.execute("CREATE VIEW transcriptomevolcano AS SELECT pt_sbst_no, type FROM rna")
    if type_ == "proteome":
        conn.execute("DROP VIEW if exists proteomevolcano")
        conn.execute("CREATE VIEW proteomevolcano AS SELECT pt_sbst_no, type FROM proteome")
    conn.commit()
    conn.close()

def create_rnid_table(db_path, rnid):
    """
    Create RNID-related tables in the database.

    This function reads data from CSV files, creates and populates tables with
    RNID-related information, and returns a dictionary mapping RNID values to IDs.

    Args:
        db_path (str): The path to the database.
        rnid (list): A list of RNID values.

    Returns:
        dict: A dictionary mapping RNID values to their corresponding IDs.
    """
    conn = sql.connect(db_path)

    df1 = pd.read_csv("static/db_files/deg_results.csv", sep=",")
    conn.execute("DROP TABLE IF EXISTS deg_results")
    df1.to_sql("deg_results", conn)
    df2 = pd.read_csv("static/db_files/interpro.csv", sep=",")
    conn.execute("DROP TABLE IF EXISTS interpro")
    df2.to_sql("interpro", conn)

    conn.execute("DROP TABLE IF EXISTS rnid")
    conn.execute(create_database["rnid"])
    rows = []
    for rnid_value in rnid:
        rows.append(
            {
                "ybc_key": rnid_value,
                "rn_key": rnid_value,
                "brst_key": rnid_value,
                "dna_mutation_rnid": False,
                # "dna_mutation": False,
                "methylation": False,
                "rnas": False,
                "phospho": False,
                "porteomes": False,
                "cnv_rnid": False,
                # "cnv": False,
                "fusion_gene": False,
                "total": 0,
                "image": 0,
            }
        )
    data_frame = pd.DataFrame(rows)
    data_frame.index = np.arange(1, len(data_frame) + 1)
    data_frame.to_sql("rnid", conn, if_exists="append",
                      index=True, index_label="id")
    cursor = conn.cursor()
    cursor.execute("select id,rn_key from rnid")
    results = cursor.fetchall()
    res = {}
    for value in results:
        res[value[1]] = value[0]
    return res


def create_master_phospho_table(db_path):
    """
    Create or append to the 'masterphospho' table in the database.

    This function reads data from a CSV file ('MasterPhospho.csv'), checks if
    the 'masterphospho' table exists in the database, and either appends the data
    if the table exists or creates a new table if it doesn't exist.

    Args:
        db_path (str): The path to the database.

    Returns:
        None
    """
    conn = sql.connect(db_path)

    df1 = pd.read_csv("static/db_files/MasterPhospho.csv", sep=",")

    # Check if the table already exists in the database
    if (
        "masterphospho"
        in conn.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()
    ):
        # Table already exists, append the data
        df1.to_sql("masterphospho", conn, if_exists="append", index=False)
    else:
        # Table doesn't exist, create a new table
        df1.to_sql("masterphospho", conn, if_exists="replace", index=False)

    conn.close()


def create_hg38_shared_table(db_path):
    """
    Create or append to the 'hg38' table in the database.

    This function reads data from a CSV file ('hg38.csv'), checks if the 'hg38'
    table exists in the database, and either appends the data if the table exists
    or creates a new table if it doesn't exist.

    Args:
        db_path (str): The path to the database.

    Returns:
        None
    """
    conn = sql.connect(db_path)

    df1 = pd.read_csv("static/db_files/hg38.csv", sep=",")

    # Check if the table already exists in the database
    if (
        "hg38"
        in conn.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()
    ):
        # Table already exists, append the data
        df1.to_sql("hg38", conn, if_exists="append", index=False)
    else:
        # Table doesn't exist, create a new table
        df1.to_sql("hg38", conn, if_exists="replace", index=False)

    conn.close()


def create_volcano_csv_file(full_path, filepath, project_id, tab):
    """
    Create a CSV file containing the data pivoted for volcano plot analysis.

    This function reads data from a provided file path, pivots the data as required for
    a volcano plot analysis, and then saves the pivoted data to a CSV file with a specific
    naming convention based on the project and tab.

    Args:
        full_path (str): The full path to the directory where the CSV file will be saved.
        filepath (str): The path to the input data file.
        project_id (int): The ID of the project associated with the data.
        tab (str): The type of data tab ("rna" or "proteome").

    Returns:
        bool: True if the CSV file is successfully created, False otherwise.
    """
    if tab == "rna":
        rna_file_pivot_table = f"{full_path}{project_id}_transcriptome.csv"
    else:
        rna_file_pivot_table = f"{full_path}{project_id}_proteome.csv"
    try:
        data_frame = pd.read_csv(filepath, sep="\t")
        if tab == "rna":
            data_frame_2 = data_frame.pivot_table(
                index="gene_name", columns="sample_id", values="raw"
            ).rename_axis(index=None, columns="id")
        else:
            data_frame_2 = data_frame.pivot_table(
                index="gene_name", columns="sample_id", values="gene_vl"
            ).rename_axis(index=None, columns="id")

        data_frame_2.to_csv(rna_file_pivot_table, index_label="id")

    except Exception as e:
        add_line_in_logger_file()
        logger.exception(e)
        return False
    return True


def delete_user_files(user_files_directory):
    for filename in os.listdir(user_files_directory):
        file_path = os.path.join(user_files_directory, filename)
        if os.path.isfile(file_path):
            os.remove(file_path)

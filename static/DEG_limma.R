# #!/usr/bin/env Rscript
# library("edgeR")
# args <- commandArgs(trailingOnly = TRUE)
# args
# input_file_name = args[1]
# output_file_name = args[2]
# group_file_name = args[3]
# control_column_number = strtoi(args[4])
# treated_column_number = strtoi(args[5])

# counts <- as.matrix(read.csv(input_file_name, row.names = 1))
# col_data <- read.csv(group_file_name, header=TRUE, sep="\t")
# sample_info_edgeR <- factor(c(rep("Control", control_column_number), rep("Treated", treated_column_number)))
# sample_info_edgeR <- relevel(sample_info_edgeR, ref =  "Control")
# edgeR.DGElist <- DGEList(counts = counts, group = sample_info_edgeR)
# summary(log2(rowSums(cpm(edgeR.DGElist))))
# keep <- rowSums(cpm(edgeR.DGElist) >=1) >=5
# edgeR.DGElist <- edgeR.DGElist [ keep ,]
# edgeR.DGElist$samples$lib.size <- colSums( edgeR.DGElist $ counts)
# edgeR.DGElist <- calcNormFactors ( edgeR.DGElist , method = "TMM" )
# design <- model.matrix(~ sample_info_edgeR)
# edgeR.DGElist <- estimateDisp(edgeR.DGElist, design)
# edger_fit <- glmFit(edgeR.DGElist, design)
# edger_lrt <- glmLRT(edger_fit)
# DGE.results_edgeR <- topTags(edger_lrt, n=Inf, sort.by = "PValue", adjust.method = "BH")
# write.table(as.data.frame(DGE.results_edgeR), file =output_file_name, row.names = T, quote = F, sep = ",")


#!/usr/bin/env Rscript
library("edgeR")
library("dplyr")

args <- commandArgs(trailingOnly = TRUE)
args
input_file_name = args[1]
output_file_name = args[2]
group_file_name = args[3]
control_column_number = strtoi(args[4])
treated_column_number = strtoi(args[5])

# load count file
counts <- as.matrix(read.csv(input_file_name, row.names = 1))

# load group file(patient clinical info.)
col_data <- read.csv(group_file_name, header=TRUE, sep="\t")

# group info. to factor
control_column_number <- sum(col_data[['Condition']] == 'Control')
treated_column_number <- sum(col_data[['Condition']] == 'Treated')
sample_info_edgeR <- factor(c(rep("Control", control_column_number), rep("Treated", treated_column_number)))
sample_info_edgeR <- relevel(sample_info_edgeR, ref =  "Control")

# count & group info. summarized in DGE object
edgeR.DGElist <- DGEList(counts = counts, group = sample_info_edgeR)

# filter out genes with low counts
## keep only genes with 'cpm >= 1' AND 'rowSums >= 5'
#summary(log2(rowSums(cpm(edgeR.DGElist))))
keep <- rowSums(cpm(edgeR.DGElist) >=1) >=5
edgeR.DGElist <- edgeR.DGElist [ keep ,]

# update lib.size
edgeR.DGElist$samples$lib.size <- colSums( edgeR.DGElist $ counts)

# add norm.factors calculations
edgeR.DGElist <- calcNormFactors ( edgeR.DGElist , method = "TMM" )

# design object prepared
design <- model.matrix(~ sample_info_edgeR)

# estimate dispersion
edgeR.DGElist <- estimateDisp(edgeR.DGElist, design)

# fit glm
## Fit a negative binomial generalized log-linear model to the read counts for each gene. Conduct genewise statistical tests for a given coefficient or coefficient contrast.
edger_fit <- glmFit(edgeR.DGElist, design)

## glmLRT conducts likelihood ratio tests for one or more coefficients in the linear model. 
edger_lrt <- glmLRT(edger_fit)

# print out statistics of DEGs
## Extracts the most differentially expressed genes (or sequence tags) from a test object, ranked either by p-value or by absolute log-fold-change.
DGE.results_edgeR <- topTags(edger_lrt, n=Inf, sort.by = "PValue", adjust.method = "BH")
DGE.results_edgeR <- as.data.frame(DGE.results_edgeR)
DGE.results_edgeR$'gene_name' <- rownames(DGE.results_edgeR)
DGE.results_edgeR <- DGE.results_edgeR[,c(6,1,2,3,4,5)]

# To change the P value notations
# DGE.results_edgeR$PValue <- sprintf("%.2e", DGE.results_edgeR$PValue)

# print out statistics of full genes
#>>>>>>>> Apply in 'Download Entire Data' button 
write.table(DGE.results_edgeR, file = output_file_name, row.names = FALSE, quote = FALSE, sep = ",")

# # print out statistics of up-DEGs(red dots)
# #>>>>>>>> Apply in 'Expression Up level: Total entries' button
# upDEG <- DGE.results_edgeR %>% filter(logFC >= 1.5, PValue <= 0.05)
# write.table(upDEG, file ='upDEG_stats.txt', row.names = FALSE, quote = FALSE, sep = ",")

# # print out statistics of down-DEGs(blue dots)
# #>>>>>>>> Apply in 'Expression Down level: Total entries' button
# downDEG <- DGE.results_edgeR %>% filter(logFC <= -1.5, PValue <= 0.05)
# write.table(downDEG, file ='downDEG_stats.txt', row.names = FALSE, quote = FALSE, sep = ",")




import scipy.stats as st


def quantified_mistake(total_size, malicious_size, sample_size, k):
    hypergeom = st.hypergeom(total_size, malicious_size, sample_size)
    median = hypergeom.median()
    rounded_median = int(round(median))

    cumulative_prob_good_pick = hypergeom.cdf(rounded_median)
    cumulative_prob_bad_pick = hypergeom.cdf(sample_size) - cumulative_prob_good_pick
    cumulative_prob_seen = hypergeom.cdf(k) - cumulative_prob_good_pick
    ratio_of_likelihood_between_good_bad_choice = \
        0 if cumulative_prob_bad_pick == 0 else cumulative_prob_good_pick / cumulative_prob_bad_pick
    dampening_factor = 0 if cumulative_prob_bad_pick == 0 else cumulative_prob_seen / cumulative_prob_bad_pick

    return ratio_of_likelihood_between_good_bad_choice * dampening_factor


if __name__ == '__main__':
    print(quantified_mistake(100, 30, 10, 5))

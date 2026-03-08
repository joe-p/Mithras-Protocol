/** The tree depth determines the anonymity set for a given root
 * Ideally we want at least 20 to give us a tree size of 1 million
 * For every increase to the depth, we do two more hashes in the lsig.
 * One hash is 1110 ops, so to calculate the budget used for a given depth:
 *
 * (1110 * DEPTH * 2)
 *
 * Dividing that by the lsig budget, we get the number of lsigs needed:
 *
 * (1110 * DEPTH * 2) / 20_000
 *
 * For a depth of 20, we get ~2.8 lsigs needed. Since there is no such thing as a fraction of an lsig,
 * we can round up to 3 lsigs and then work backwards to find the max depth we can support with 3 lsigs:
 *
 * (20_000 * 3) / (1110 * 2) = 27.02
 *
 * To give extra room for other ops we'll go down to 26, which gives us a tree size of 67 million
 */
export const TREE_DEPTH = 26;
